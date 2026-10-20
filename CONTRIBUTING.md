# Contributing to Kinetic Trust Library

Thank you for helping improve Kinetic Trust Library. This repository is an
informative Python reference library for selected KTP v2.1.0 protocol
primitives. It is not a product, deployed Oracle, policy enforcement point, or
certification program.

## When an issue is required

Open an issue before proposing a change that affects any of these boundaries:

- interpretation of a KTP RFC or released conformance artifact;
- a public Python interface or wire representation;
- compatibility or versioning;
- a cryptographic or security boundary; or
- ownership between Library, Service, and consuming products.

A direct pull request is appropriate for a bounded defect, documentation or
test correction, dependency update, or internal refactor that does not cross
one of those boundaries.

Protocol changes belong in the
[official KTP RFC repository](https://github.com/nmcitra/ktp-rfc). This
implementation repository must not silently establish a new protocol contract.

## Consequential proposals

For a consequential issue and its pull request, identify:

- the pinned KTP tag and relevant section or released artifact;
- current behavior and proposed behavior;
- compatibility and versioning impact;
- vector or test evidence and the limits of that evidence;
- the responsible Library, Service, or product owner; and
- alternatives considered.

Keep one coherent decision in each pull request. Link the issue when the change
falls into an issue-required category; otherwise a linked issue is optional.

## Local verification

Run commands from the repository root. The base library has no third-party
runtime dependency:

```console
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
python3 tools/run_required_tests.py --start-dir tests/unit --top-level-dir .
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
python3 tools/compile_catalog.py --check
```

Install the optional adapter and run its separate evidence lanes when the
change can affect cryptography or provider contracts:

```console
python3 -m pip install '.[cryptography]'
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
python3 tools/run_required_tests.py --start-dir tests_crypto --top-level-dir .
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
python3 tools/run_required_tests.py --start-dir tests_provider --top-level-dir .
```

Follow [the ordinary release procedure](docs/releasing.md) for an exact wheel
and source-distribution check. Passing tests, vectors, package checks, or
CodeQL is bounded evidence about the Library; it is not product, deployment,
or certification conformance.

## Security and conduct

Do not disclose a suspected vulnerability in a public issue. Follow
[SECURITY.md](SECURITY.md) instead. Participation is governed by the
[Contributor Covenant](CODE_OF_CONDUCT.md).
