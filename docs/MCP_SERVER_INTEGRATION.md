# Raw MCP server integration

WarrantKit can protect synchronous Python handlers used to implement tools on a raw Model Context Protocol (MCP) server. The MCP server and transport are not the security boundary: register the WarrantKit-wrapped handler so every consequential call crosses the controller-owned AgentContainment ActionGateway.

## Install

Install WarrantKit's MCP extra and use the MCP Python SDK for your server:

    python -m pip install "warrantkit[mcp]"

## Protect a handler

Wrap the actual side-effecting Python function before registering it with the server:

    from mcp.server.fastmcp import FastMCP
    from agentcontain.integrations.mcp import wrap_mcp_tool

    mcp = FastMCP("payments")

    def payments_refund(order_id: str, amount: int) -> str:
        """Issue a payment refund."""
        # Keep real payment credentials in the trusted service boundary.
        return payment_service.refund(order_id, amount)

    protected_refund = wrap_mcp_tool(
        payments_refund,
        admission,  # signed Warrant grants payments_refund
        gateway,    # ActionGateway owned by the admitted runtime's controller
        warrant_verifier=verifier,  # independently provisioned Ed25519 public key
        capability="payments_refund",
        resource="payments-api",
    )

    mcp.tool()(protected_refund)

The example assumes admission, gateway, verifier, and payment_service are initialized by the trusted host application. Register the wrapped handler in place of the original function, not alongside it. If an unprotected route to the same side effect remains reachable, the protected wrapper cannot secure that bypass.

## Enforcement contract

For every invocation, the wrapper:

1. Acquires a controller-owned execution lease before Warrant verification.
2. Verifies the signed Warrant against the pinned admission, accepted policy, current runtime identity, and epoch.
3. Checks the explicit capability required for this handler.
4. Executes the original synchronous handler through ActionGateway using the same lease acquired before verification.
5. Fails closed if the runtime lease is unavailable, authority is stale, the capability is absent, or the gateway denies the action.

The exact lease is important: if containment or recovery changes the runtime epoch after Warrant verification, the gateway must reject that invocation rather than allowing it to acquire a fresh lease for a previously authorized call.

## Scope and limitations

- This adapter wraps synchronous Python handlers. It rejects coroutine functions; async-native MCP tool execution is not claimed.
- It protects only calls routed through the wrapped handler and gateway. It does not automatically protect remote MCP servers, hosted tools, direct service calls, or alternate endpoints.
- Keep downstream credentials outside the agent process. If the agent can invoke the protected service directly with an unrestricted credential, the gateway is advisory.
- The Warrant and runtime lease remain separate checks. The Warrant authenticates authority relative to an independently trusted public key; the gateway's controller-owned lease is the final side-effect enforcement point.
- This adapter does not claim kernel-level process containment by itself. Use WarrantKit's Linux cgroup-v2 proof for that separate claim.

The adapter intentionally has no hard dependency on the MCP SDK. It wraps the synchronous handler at the side-effect boundary and can therefore be used with an MCP server implementation that registers Python callables.
