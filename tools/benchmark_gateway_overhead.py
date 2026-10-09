#!/usr/bin/env python3
"""Microbenchmark the real WarrantKit LangChain wrapper and ActionGateway.

No LLM, network, or external service is involved. Results are local-process
measurements, not production capacity claims. Run after installing the repo and
its LangChain extra:
  python tools/benchmark_gateway_overhead.py --calls 10000 --warmup 500 --concurrency 1,4,16
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace
from datetime import datetime, timezone

from langchain_core.tools import tool
from agent_containment.gateway import ActionGateway
from agent_containment.policy import PolicyEngine
from agentcontain import Policy, admit, build_agentcontainment_engine
from agentcontain.integrations.langchain import wrap_langchain_tool
from agentcontain.integrations.langchain_middleware import WarrantKitMiddleware


@tool
def noop_tool(value: int) -> int:
    """Return the input without doing I/O; isolates wrapper overhead."""
    return value


def summarize(samples_ns: list[int], total_seconds: float) -> dict[str, float | int]:
    ordered = sorted(samples_ns)
    def pct(p: float) -> float:
        return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * p))] / 1_000
    return {
        "calls": len(samples_ns),
        "throughput_calls_s": round(len(samples_ns) / total_seconds, 1),
        "latency_us_p50": round(statistics.median(samples_ns) / 1_000, 2),
        "latency_us_p95": round(pct(0.95), 2),
        "latency_us_p99": round(pct(0.99), 2),
        "latency_us_mean": round(statistics.fmean(samples_ns) / 1_000, 2),
    }


def measure(call, count: int) -> dict[str, float | int]:
    samples: list[int] = []
    start_all = time.perf_counter()
    for i in range(count):
        start = time.perf_counter_ns()
        result = call(i)
        elapsed = time.perf_counter_ns() - start
        if result != i:
            raise AssertionError(f"unexpected tool result at {i}: {result!r}")
        samples.append(elapsed)
    elapsed_all = time.perf_counter() - start_all
    return summarize(samples, elapsed_all)


def measure_concurrent(
    call, count: int, workers: int, warmup: int = 0
) -> dict[str, float | int]:
    """Measure simultaneous worker loops, with warmup outside timed samples."""
    counts = [count // workers + (1 if i < count % workers else 0) for i in range(workers)]
    warmup_counts = [
        warmup // workers + (1 if i < warmup % workers else 0)
        for i in range(workers)
    ]
    start_barrier = Barrier(workers + 1)

    def run_worker(worker_id: int, worker_calls: int, worker_warmup: int) -> list[int]:
        samples: list[int] = []
        for i in range(worker_warmup):
            value = -(sum(warmup_counts[:worker_id]) + i + 1)
            result = call(value)
            if result != value:
                raise AssertionError(f"unexpected warmup result at {value}: {result!r}")
        start_barrier.wait()
        base = worker_id * count
        for offset in range(worker_calls):
            value = base + offset
            started = time.perf_counter_ns()
            result = call(value)
            elapsed = time.perf_counter_ns() - started
            if result != value:
                raise AssertionError(f"unexpected tool result at {value}: {result!r}")
            samples.append(elapsed)
        return samples

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(run_worker, worker_id, worker_count, warmup_counts[worker_id])
            for worker_id, worker_count in enumerate(counts)
        ]
        start_all = time.perf_counter()
        start_barrier.wait()
        worker_samples = [future.result() for future in futures]
        elapsed_all = time.perf_counter() - start_all

    samples = [sample for worker_samples_for_thread in worker_samples for sample in worker_samples_for_thread]
    result = summarize(samples, elapsed_all)
    result["workers"] = workers
    result["warmup_total"] = warmup
    result["warmup_calls_by_worker"] = warmup_counts
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--calls", type=int, default=10_000)
    parser.add_argument("--warmup", type=int, default=500)
    parser.add_argument("--concurrency", default="1,4,16", help="comma-separated worker counts for concurrent tests")
    args = parser.parse_args()
    if args.calls < 100 or args.warmup < 0:
        parser.error("--calls must be >=100 and --warmup must be >=0")
    try:
        concurrency = sorted({int(value) for value in args.concurrency.split(",")})
    except ValueError:
        parser.error("--concurrency must be comma-separated positive integers")
    if not concurrency or any(value < 1 for value in concurrency):
        parser.error("--concurrency must contain positive worker counts")

    engine = build_agentcontainment_engine("gateway-benchmark")
    admission = admit(
        Policy("benchmark", capabilities=("noop_tool",)),
        agent_id="gateway-benchmark",
        engine=engine,
        runtime_id=engine.runtime_id,
    )
    # ActionGateway retains its full decision history by default; do not silently truncate evidence.
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    protected = wrap_langchain_tool(noop_tool, admission, gateway)
    middleware = WarrantKitMiddleware(admission, gateway)

    # Warm both code paths before collecting samples.
    for i in range(args.warmup):
        noop_tool.invoke({"value": i})
        protected.invoke({"value": i})
        middleware.wrap_tool_call(
            SimpleNamespace(tool=noop_tool, value=i),
            lambda request: noop_tool.invoke({"value": request.value}),
        )

    direct = measure(lambda i: noop_tool.invoke({"value": i}), args.calls)
    guarded = measure(lambda i: protected.invoke({"value": i}), args.calls)
    # Measures the native middleware hook around the same LangChain tool
    # invocation, excluding the outer agent orchestration overhead.
    middleware_result = measure(
        lambda i: middleware.wrap_tool_call(
            SimpleNamespace(tool=noop_tool, value=i),
            lambda request: noop_tool.invoke({"value": request.value}),
        ),
        args.calls,
    )
    overhead_us = guarded["latency_us_p50"] - direct["latency_us_p50"]
    result = {
        "benchmark": "WarrantKit LangChain wrapper + AgentContainment ActionGateway",
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "calls_per_path": args.calls,
        "warmup_per_path": args.warmup,
        "tool": "in-process no-op; no LLM/network/I/O",
        "direct_langchain_tool": direct,
        "warrantkit_protected_tool_wrapper": guarded,
        "warrantkit_native_middleware_hook_noop_handler": middleware_result,
        "overhead": {
            "p50_additional_us": round(overhead_us, 2),
            "throughput_ratio_protected_over_direct": round(guarded["throughput_calls_s"] / direct["throughput_calls_s"], 3),
        },
        "gateway_history_entries_after_measurement": len(gateway.history),
        "limitations": [
            "threaded in-process benchmark; does not model separate processes or end-to-end agent orchestration",
            "in-process no-op tool isolates control-path cost and is not representative of slow real tools",
            "middleware-hook measurement excludes LangChain agent orchestration and is not an end-to-end agent throughput result",
            "results vary with CPU, Python, dependency versions, and host load",
        ],
    }
    # Each concurrent path uses a fresh runtime/gateway so one run cannot affect
    # another through shared policy state. This measures threaded callers, not
    # separate processes or end-to-end LLM orchestration.
    concurrent_results = {}
    for workers in concurrency:
        concurrent_engine = build_agentcontainment_engine(f"gateway-benchmark-{workers}")
        concurrent_admission = admit(
            Policy("benchmark", capabilities=("noop_tool",)),
            agent_id=f"gateway-benchmark-{workers}",
            engine=concurrent_engine,
            runtime_id=concurrent_engine.runtime_id,
        )
        wrapper_gateway = ActionGateway(PolicyEngine(), concurrent_engine.controller)
        concurrent_protected = wrap_langchain_tool(noop_tool, concurrent_admission, wrapper_gateway)

        middleware_engine = build_agentcontainment_engine(f"gateway-middleware-benchmark-{workers}")
        middleware_admission = admit(
            Policy("benchmark", capabilities=("noop_tool",)),
            agent_id=f"gateway-middleware-benchmark-{workers}",
            engine=middleware_engine,
            runtime_id=middleware_engine.runtime_id,
        )
        middleware_gateway = ActionGateway(PolicyEngine(), middleware_engine.controller)
        concurrent_middleware = WarrantKitMiddleware(middleware_admission, middleware_gateway)

        direct_concurrent = measure_concurrent(
            lambda i: noop_tool.invoke({"value": i}), args.calls, workers, args.warmup
        )
        protected_concurrent = measure_concurrent(
            lambda i: concurrent_protected.invoke({"value": i}), args.calls, workers, args.warmup
        )
        middleware_concurrent = measure_concurrent(
            lambda i: concurrent_middleware.wrap_tool_call(
                SimpleNamespace(tool=noop_tool, value=i),
                lambda request: noop_tool.invoke({"value": request.value}),
            ), args.calls, workers, args.warmup
        )
        expected_decisions = args.calls + args.warmup
        wrapper_decisions = len(wrapper_gateway.history)
        middleware_decisions = len(middleware_gateway.history)
        if wrapper_decisions != expected_decisions:
            raise AssertionError(
                f"expected {expected_decisions} wrapper gateway decisions at concurrency {workers}, "
                f"recorded {wrapper_decisions}"
            )
        if middleware_decisions != expected_decisions:
            raise AssertionError(
                f"expected {expected_decisions} middleware gateway decisions at concurrency {workers}, "
                f"recorded {middleware_decisions}"
            )
        concurrent_results[str(workers)] = {
            "direct_langchain_tool": direct_concurrent,
            "warrantkit_protected_tool_wrapper": protected_concurrent,
            "warrantkit_native_middleware_hook": middleware_concurrent,
            "wrapper_gateway_decisions_recorded": wrapper_decisions,
            "middleware_gateway_decisions_recorded": middleware_decisions,
        }
    result["concurrent_threaded_runs"] = concurrent_results
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
