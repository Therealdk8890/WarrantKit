# Get started with WarrantKit

This guide gets you from a clean checkout to a reproducible framework-to-gateway proof, then points you to the integration that fits your application.

## Before you start

- Python 3.11 or newer
- Git
- A supported development environment for the selected framework

You do not need an LLM API key or real payment/database credentials to run the deterministic proof below.

## 1. Run the framework-to-gateway proof

Start here if you want to see what WarrantKit actually protects before integrating it into an application.

```bash
git clone --recurse-submodules https://github.com/Therealdk8890/WarrantKit.git
cd WarrantKit
python -m pip install ".[langchain]"
python tools/run_authority_boundary_demo.py
```

The proof uses a real LangChain tool and AgentContainment's ActionGateway without an LLM, network access, or real credentials. It exercises an allowed side effect, advances containment state, and checks that a retained pre-containment Warrant is rejected before a second side effect occurs.

**What this establishes:** the tested framework adapter checks current Warrant authority and routes the protected action through the controller-owned gateway.

**What it does not establish:** kernel-enforced process termination, universal host isolation, reversal of completed side effects, or protection of action paths that bypass the gateway.

## 2. Choose your application integration

Install the optional extra for the framework you use:

```bash
python -m pip install "warrantkit[langchain]"
python -m pip install "warrantkit[crewai]"
python -m pip install "warrantkit[openai-agents]"
```

Run only the command for your framework. For a checkout-based development install, use the extra-install command in step 1 instead.

- **LangChain:** start with the [native middleware integration](INTEGRATIONS_AND_PROOFS.md#native-middleware-path) for existing tool objects, or the [wrapper integration](INTEGRATIONS_AND_PROOFS.md#langchain-integration).
- **OpenAI Agents SDK:** follow the [local function-tool integration](INTEGRATIONS_AND_PROOFS.md#openai-agents-sdk-integration). This path protects synchronous Python functions; it does not wrap OpenAI-hosted tools executing outside your application runtime.
- **CrewAI:** follow the [CrewAI integration guide](INTEGRATIONS_AND_PROOFS.md#crewai-integration).

The optional extras install framework dependencies; they do not configure policy, issue Warrants, provision trusted keys, or create a deployment's enforcement boundary for you. Use the complete guide for imports and setup rather than copying an abbreviated snippet without its signer, verifier, admission, and gateway configuration.

## 3. Understand the deployment boundary

Before protecting a consequential operation:

1. Keep downstream credentials out of the agent process where practical. If the agent can perform the same side effect directly with an unrestricted credential, the gateway can be bypassed.
2. Configure the Warrant signer and independently trusted verification key for your deployment. Do not use an ephemeral demo key as a production trust anchor.
3. Keep the adapter's Warrant check and ActionGateway's controller-owned lease enforcement distinct. They protect different boundaries.
4. Test denial and stale-authority behavior in your own integration before relying on it.

The portable `warrantkit demo` is useful for orientation, but it is simulated and is **not** proof of kernel-level containment. For real process-containment evidence, follow the environment-gated [Linux cgroup-v2 real-kill guide](REAL_KILL_DEMO.md). It requires Linux and suitable root or delegated cgroup privileges.

## If something fails

- **Import or dependency errors:** confirm Python is 3.11+ and install the extra for the framework you are using.
- **Submodule or `agent_containment` import errors:** make sure you cloned with `--recurse-submodules` and run the proof from the repository root.
- **You need real process-kill evidence:** do not infer it from the portable demo or framework proof; follow the Linux cgroup-v2 guide and its prerequisites.

For the full adapter details, evidence interpretation, and implementation status, see [Integrations and proofs](INTEGRATIONS_AND_PROOFS.md).
