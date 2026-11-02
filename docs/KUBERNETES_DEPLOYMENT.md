# Kubernetes Deployment Considerations

**Status: deployment guidance only. This document does not claim a supported Kubernetes operator, Helm chart, DaemonSet, or turnkey production deployment.**

WarrantKit's host-enforcement proof uses Linux cgroup v2 through the separate AgentContainment runtime engine. Kubernetes can host the workload, but it does not remove or automatically satisfy the host-level enforcement requirements.

## What must be true

A Kubernetes evaluation must establish all of the following on the actual target nodes:

- The node operating system is Linux.
- The node uses a unified cgroup v2 hierarchy.
- The runtime and kubelet cgroup configuration are compatible with the cgroup-v2 path being exercised.
- The enforcement controller can identify the exact workload cgroup and has the required root or explicitly delegated authority over the intended subtree.
- The controller is outside the agent's trust boundary. The agent must not be able to modify, replace, or disable the controller or its enforcement state.
- The controller can observe and verify the workload's terminal state and the relevant cgroup population after containment.
- Any eBPF-based egress enforcement is separately validated for the node kernel, attachment point, privileges, lifecycle, and cleanup behavior.

A successful container-level test is not evidence that a Kubernetes deployment satisfies these conditions.

## Placement model to evaluate

The security-relevant separation is between the untrusted agent workload and the trusted enforcement controller.

A candidate architecture for an evaluation is:

1. Run the agent in its ordinary workload Pod with no direct access to unrestricted downstream credentials.
2. Run the controller in a separately administered node-level component or another deployment arrangement that provides a deliberately delegated cgroup subtree and the required host visibility.
3. Ensure the agent cannot access the controller's private signing material, control socket, cgroup-management interface, or privileged credentials.
4. Bind the controller to the exact workload identity and cgroup path; do not infer identity from a mutable Pod name alone.
5. Test containment and stale-authority rejection against a representative workload, including restarts, rescheduling, and cgroup recreation.
6. Preserve the node kernel, container runtime, cgroup configuration, controller revision, workload identity, and verifier output with the evaluation record.

This is an evaluation model, not a validated deployment recipe. The repository does not currently ship a Kubernetes controller, admission webhook, CRD, Helm chart, or production DaemonSet manifest.

## Avoid unsafe assumptions

- **Do not assume a privileged Pod is automatically a safe controller.** Privilege broadens the blast radius. The controller's image, service account, host mounts, capabilities, network exposure, and update path become part of the trusted computing base.
- **Do not mutate kubelet-owned cgroups ad hoc.** Establish a supported delegation boundary and verify that the runtime and kubelet continue to manage their own hierarchy correctly.
- **Do not treat Pod deletion as proof of containment.** The proof must inspect the process/cgroup state at the enforcement boundary and verify that stale authority is rejected.
- **Do not assume a Pod identity is a stable runtime identity.** Kubernetes can replace Pods and containers. The integration must bind the authority to a runtime identity/epoch that changes when the underlying execution boundary changes.
- **Do not leave alternate credentials or side-effect routes available to the agent.** A direct call to a downstream API bypasses a gateway that the call never traverses.
- **Do not infer eBPF support from cgroup v2 alone.** Kernel configuration, program type support, attachment permissions, and lifecycle behavior must be tested independently.

## Minimum Kubernetes evaluation record

| Area | Required evidence |
|---|---|
| Node | Linux distribution, kernel release, architecture |
| Cgroups | cgroup v2 mount, hierarchy, delegation owner and subtree |
| Runtime | containerd / CRI-O version and cgroup driver |
| Kubernetes | version, kubelet configuration, node security policy |
| Controller | placement, service account, host access, capabilities, secret boundary |
| Workload | Pod/UID, container ID, cgroup path, restart/reschedule behavior |
| Enforcement | process exit, cgroup population, egress enforcement if used |
| Authority | Warrant identity, runtime ID, epoch before/after containment, stale-Warrant rejection |
| Evidence | exact source revisions, bundle verifier output, independent trust-anchor provenance |
| Limitations | bypass routes, privileges, untested paths, operational impact |

## Current support statement

The reproducible host-containment claim is limited to the Linux cgroup-v2 environment and privilege model documented in the [real-kill guide](REAL_KILL_DEMO.md). Kubernetes is a possible orchestration environment for a separately validated deployment, not a currently certified or turnkey integration.

A Kubernetes deployment should not be described as supported until a repeatable test has exercised the actual node/runtime combination, cgroup delegation model, controller isolation, workload termination, stale-authority rejection, and evidence verification.
