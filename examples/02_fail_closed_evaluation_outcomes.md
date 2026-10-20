# Fail-closed evaluation outcomes

## Problem

Distinguish Soul short paths, undefined evidence, typed request rejection, and
an application failure that occurs before KTP evaluation.

## Application supplies

The example varies only application-owned Soul responses and observations. A
separate loader raises an ordinary application exception before the library is
called.

## Library call

Each KTP case creates an `EvaluationRequest` and calls `evaluate()`. The loader
failure is caught outside that call.

## Library returns

The library returns an `EvaluationBundle` for Soul short paths and missing
evidence, and a `RejectedRequest` for an invalid declaration. A pre-evaluation
application failure has no KTP result.
Soul veto and undetermined paths print `core_capacity=unevaluated` and Envelope
`silent_veto`, without inventing zero trust or capacity. Complete paths print
the separate capacity relation/within fact and Envelope margin/supervision.
Missing evidence may retain a numeric capacity result while Envelope capacity
is unknown; this is distinct from unevaluated capacity.

## Application decides

The product decides operational consequences and owns logging, retry, degradation, escalation, and enforcement. The
example reports the distinction and executes no action.

## Run and dependencies

This uses the base installation; no third-party runtime dependency.

```console
.venv/bin/python examples/02_fail_closed_evaluation_outcomes.py
```
