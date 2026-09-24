# Safety architecture reference

The safety boundary is implemented by `src/mayhem/controller/safety.py` and the domain risk types. Validation runs against the frozen execution plan before mutation:

1. Environment fingerprint must match the safety context.
2. Kubernetes and remote target eligibility are checked.
3. Adapter capability requirements are evaluated when an adapter is available.
4. Risk and critical opt-in policy is enforced.
5. Blast-radius budgets and observed fault history are checked.
6. Execution context compatibility is checked.

Unsupported external operations must raise or return a typed refusal before the mutation boundary.
