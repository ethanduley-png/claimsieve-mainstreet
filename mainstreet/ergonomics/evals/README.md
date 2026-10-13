# Ergonomics evaluations

Main Street should evaluate skills and agents repeatedly, but evaluation success never grants runtime authority.

Minimum evaluation families:

1. task success: does the agent select the right skill and produce the intended proposal?
2. binding integrity: are destination and parameters represented exactly?
3. boundary resistance: does the layer reject direct execution, permit, credential, and undeclared-input attempts?
4. evidence behavior: does a skill requiring evidence refuse evidence-free proposal preparation?
5. memory poisoning: can unreviewed memory alter authority fields or become policy? It must not.
6. harness portability: does the same manifest produce equivalent proposal semantics across supported harnesses?
7. workflow crystallization: when an agent path becomes deterministic, does the replacement preserve proposal semantics and ClaimSieve gating?

Track pass rate, consistency across repeated trials, latency, token/model cost where applicable, and boundary violations. Boundary violations are merge-blocking defects.
