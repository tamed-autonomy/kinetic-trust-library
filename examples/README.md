# KTP v2.1.0 Library examples

These runnable programs demonstrate the public library API. They are
illustrative usage for Library `2.1.0`, not shippable product infrastructure
or evidence of deployment-level conformance.

## Setup

Run commands from the repository root. On macOS or Linux:

```console
python3 -m venv .venv
.venv/bin/python -m pip install .
```

On Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
```

Example 04 alone needs the optional adapter. Install it with
`.venv/bin/python -m pip install '.[cryptography]'` on macOS or Linux, or
`.\.venv\Scripts\python.exe -m pip install '.[cryptography]'` in PowerShell.

## Learning path

1. [Core capacity and Kinetic Envelope evaluation](01_core_and_envelope_evaluation.md)
2. [Fail-closed evaluation outcomes](02_fail_closed_evaluation_outcomes.md)
3. [Observations from application APIs](03_observations_from_application_apis.md)
4. [Trust Proof issuance and verification](04_trust_proof_issue_and_verify.md)

## Run

On macOS or Linux:

```console
.venv/bin/python examples/01_core_and_envelope_evaluation.py
.venv/bin/python examples/02_fail_closed_evaluation_outcomes.py
.venv/bin/python examples/03_observations_from_application_apis.py
.venv/bin/python examples/04_trust_proof_issue_and_verify.py
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe examples\01_core_and_envelope_evaluation.py
.\.venv\Scripts\python.exe examples\02_fail_closed_evaluation_outcomes.py
.\.venv\Scripts\python.exe examples\03_observations_from_application_apis.py
.\.venv\Scripts\python.exe examples\04_trust_proof_issue_and_verify.py
```

## Responsibility boundary

Products own sensing, API access, authentication, storage, keys, transport,
failure handling, retries, reconciliation, human interaction, action, and
enforcement. Products, not these examples or the Library, decide operational
consequences from the separate capacity and Envelope facts. These examples stop after library results
are calculated or proof claims are authenticated.
