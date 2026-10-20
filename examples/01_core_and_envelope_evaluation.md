# Core capacity and Kinetic Envelope evaluation

## Problem

Evaluate one already-described action against an explicit deployment profile
and current application-supplied facts.

## Application supplies

The example supplies a validated action and capability, deployment profile,
standing declaration, Soul responses, observations, operation ID, and cutoff.
These values stand in for facts a real application obtains and validates.

## Library call

The script creates an `EvaluationRequest` and calls `evaluate()` once.

## Library returns

A complete `EvaluationBundle` contains the prepared evidence, risk, `E_base`,
`E_trust`, trust tier, a separate `core_capacity` result, and `envelope`.
The fixture has demand 40 and Effective Trust about 25.12, so it reports
`above_capacity`/`within_capacity=False` and Envelope `silent_veto`. The script
prints stable fields and does not execute the described action.

## Application decides

The product decides all operational consequences from the two returned facts.
At exact equality, KTP-Core reports `AT_CAPACITY`/within while the released
zero-threshold Envelope reports zero-margin `SILENT_VETO`; its policy code
`KINETIC_CAPACITY_EXCEEDED` does not make equality Core-above-capacity. The
library does not enforce, persist, retry, present, or claim application
conformance.

## Run and dependencies

This uses the base installation; no third-party runtime dependency.

```console
.venv/bin/python examples/01_core_and_envelope_evaluation.py
```
