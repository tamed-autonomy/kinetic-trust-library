# Observations from application APIs

## Problem

Translate already-fetched domain API data into explicit KTP observation
declarations without hiding source availability or timing.

## Application supplies

The example supplies fixed dictionaries for compute readings, an unavailable
alarm source, and a published index. Small application-owned functions validate
their field types and map them to declared signals, domains, units, observation
classes, and measurement envelopes.

## Library call

The mapped declarations are placed in an `EvaluationRequest`, then `evaluate()`
performs evidence selection and the remaining deterministic Library computation.

## Library returns

The `EvaluationBundle` preserves the selected newest compute reading, the
undefined reason for the unavailable alarm source, and the selected published
index. It also contains the resulting risk, trust, separate `core_capacity` and `envelope` values. The script prints
the numerical capacity relation/within fact alongside Envelope
margin/supervision; neither is an execution instruction.

## Application decides

The product decides operational consequences and owns clients, credentials, polling, provenance meaning, and each
field-to-signal mapping. This example makes no network call and performs no
enforcement.

## Run and dependencies

This uses the base installation; no third-party runtime dependency.

```console
.venv/bin/python examples/03_observations_from_application_apis.py
```
