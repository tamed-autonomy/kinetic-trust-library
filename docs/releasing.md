# Ordinary release procedure

This procedure verifies Kinetic Trust Library `2.1.0` from one clean, reviewed
commit as an ordinary wheel and source distribution. The Library profiles KTP
`v2.1.0` at `15520035267546e1035aad7beea0cc3cf9ef8f2c`; package `major.minor`
tracks the RFC series while package patch releases may advance independently.
Do not change versions as part of verification.

## Publication boundary

The repository contains a tag-triggered Trusted Publishing workflow, but its
presence does not authorize a release. Pushing a matching version tag starts
publication; it is not a dry run. Tag creation and package publication require
separate approval after the checks below are complete.

The workflow deliberately separates an unprivileged build job from its
OIDC-enabled publish job. It builds the wheel and source distribution once,
retains those exact files as a workflow artifact, and publishes those same
bytes. The official PyPI action produces Sigstore attestations by default.
No PyPI password or API token belongs in GitHub secrets.

## One-time Trusted Publishing setup

Before the first tag is pushed, configure a pending PyPI Trusted Publisher with
these exact values:

- PyPI project: `kinetic-trust-library`
- GitHub owner: `tamed-autonomy`
- GitHub repository: `kinetic-trust-library`
- workflow filename: `release.yml`
- environment: `pypi`

Create the matching GitHub `pypi` environment. Restrict its deployments to
tags matching `v*` and require approval by the designated release reviewer.
Under the current single-maintainer governance model, allow that maintainer to
approve a deployment they initiated. If an independent release reviewer is
formally appointed, prevent the initiator from approving their own deployment.
Adjust the tag ruleset so an authorized maintainer can create a new tag while
tag updates and deletions remain blocked.
Do not weaken branch protection or permit mutable release tags. The workflow
also rejects a tag whose target is not reachable from `main`.

## Publication sequence

1. Complete every verification step in this document from the exact reviewed
   commit on `main`, and require the repository's CI and CodeQL checks to pass.
2. Confirm the Trusted Publisher, GitHub environment, and immutable-tag rules
   above are active. Confirm the tag will equal `v` plus the project version;
   for this release it is `v2.1.0`.
3. Obtain separate approval to publish. Create and locally verify a signed,
   annotated `v2.1.0` tag on the reviewed commit. Pushing that tag starts
   `.github/workflows/release.yml` and publishes to PyPI.
4. Require the release workflow to succeed, verify the PyPI project metadata
   and provenance, and install `kinetic-trust-library==2.1.0` in a fresh
   environment from PyPI.
5. Publish Kinetic Trust Service only after this exact Library release is
   visible and installable from PyPI.

## Supported source suites

Run each existing required-test suite and the pinned catalogue check on
CPython 3.11 through 3.15. Required tests must pass with zero skips. The base wrapper
runs Examples 01–03; the optional cryptography suite runs Example 04. Provider
contract tests and catalogue checks are separately required on all five interpreters.

```console
set -euo pipefail
for KTP_PYTHON_VERSION in 3.11 3.12 3.13 3.14 3.15; do
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
    uv run --python "$KTP_PYTHON_VERSION" --no-project python \
    tools/run_required_tests.py --start-dir tests/unit --top-level-dir .
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
    uv run --python "$KTP_PYTHON_VERSION" \
    --with 'cryptography>=50.0.0,<51' --no-project python \
    tools/run_required_tests.py --start-dir tests_crypto --top-level-dir .
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
    uv run --python "$KTP_PYTHON_VERSION" \
    --with 'cryptography>=50.0.0,<51' --no-project python \
    tools/run_required_tests.py --start-dir tests_provider --top-level-dir .
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src \
    uv run --python "$KTP_PYTHON_VERSION" --no-project python \
    tools/compile_catalog.py --check
done
```

## Freeze and inspect the exact artifacts

Commit reviewed changes first, then freeze the SHA. Build only into a new,
deterministic temporary directory keyed by that SHA; never reuse an earlier
artifact directory or treat source-checkout tests as installed-artifact evidence.
CI uses the pinned `build==1.5.0` frontend and the same project build backend.

```console
set -euo pipefail
test -z "$(git status --porcelain)"
KTP_REVIEWED_LIBRARY_COMMIT="$(git rev-parse HEAD)"
KTP_LIBRARY_TEMP_ROOT="${TMPDIR:-/tmp}"
KTP_LIBRARY_ARTIFACT_ROOT="${KTP_LIBRARY_TEMP_ROOT%/}/ktp-library-2.1.0-$KTP_REVIEWED_LIBRARY_COMMIT"
test ! -e "$KTP_LIBRARY_ARTIFACT_ROOT"
mkdir -p "$KTP_LIBRARY_ARTIFACT_ROOT"
uv run --python 3.11 --with 'build==1.5.0' --no-project \
  python -m build --outdir "$KTP_LIBRARY_ARTIFACT_ROOT/dist" .
KTP_LIBRARY_WHEEL="$KTP_LIBRARY_ARTIFACT_ROOT/dist/kinetic_trust_library-2.1.0-py3-none-any.whl"
KTP_LIBRARY_SDIST="$KTP_LIBRARY_ARTIFACT_ROOT/dist/kinetic_trust_library-2.1.0.tar.gz"
test -f "$KTP_LIBRARY_WHEEL"
test -f "$KTP_LIBRARY_SDIST"
test "$(find "$KTP_LIBRARY_ARTIFACT_ROOT/dist" -maxdepth 1 -name '*.whl' | wc -l)" -eq 1
test "$(find "$KTP_LIBRARY_ARTIFACT_ROOT/dist" -maxdepth 1 -name '*.tar.gz' | wc -l)" -eq 1
shasum -a 256 "$KTP_LIBRARY_ARTIFACT_ROOT"/dist/*
python3 -m zipfile -l "$KTP_LIBRARY_WHEEL"
tar -tzf "$KTP_LIBRARY_SDIST"
```

Apply the archive assertions in the existing [CI package job](../.github/workflows/ci.yml)
to these exact files. Require metadata name/version `kinetic-trust-library` /
`2.1.0`, license expression `Apache-2.0`, and Specification URL
`https://github.com/nmcitra/ktp-rfc/tree/v2.1.0`. The only `Requires-Dist` must
be the extra-qualified PyCA declaration; there are no base dependencies.
All wheel payload paths must belong to `kinetic_trust_library`. The sdist must
contain only that source package and include README, LICENSE, NOTICE, and
examples. The retired source namespace must be absent.

## Fresh offline installation and sdist examples

Create a fresh environment outside the checkout, install only the exact wheel
offline without dependencies, and run with an empty `PYTHONPATH`. Apply the
isolated import and distribution-absence assertions from the same CI package
job; require the installed Library version and specification tag, all five
supported public imports, and absence of the retired import and distribution.

Continue in the same shell so the frozen paths remain available:

```console
test -z "$(git status --porcelain)"
uv venv --python 3.11 "$KTP_LIBRARY_ARTIFACT_ROOT/venv"
uv pip install --python "$KTP_LIBRARY_ARTIFACT_ROOT/venv/bin/python" \
  --no-index --no-deps "$KTP_LIBRARY_WHEEL"
mkdir -p "$KTP_LIBRARY_ARTIFACT_ROOT/sdist"
tar -xzf "$KTP_LIBRARY_SDIST" -C "$KTP_LIBRARY_ARTIFACT_ROOT/sdist"
cd "$KTP_LIBRARY_ARTIFACT_ROOT"
PYTHONPATH= "$KTP_LIBRARY_ARTIFACT_ROOT/venv/bin/python" -I -c \
  'import kinetic_trust_library, kinetic_trust_library.core, kinetic_trust_library.proofs, kinetic_trust_library.protocols; assert callable(kinetic_trust_library.validate_absolute_uri)'
KTP_LIBRARY_SDIST_ROOT="$KTP_LIBRARY_ARTIFACT_ROOT/sdist/kinetic_trust_library-2.1.0"
PYTHONPATH= "$KTP_LIBRARY_ARTIFACT_ROOT/venv/bin/python" \
  "$KTP_LIBRARY_SDIST_ROOT/examples/01_core_and_envelope_evaluation.py"
PYTHONPATH= "$KTP_LIBRARY_ARTIFACT_ROOT/venv/bin/python" \
  "$KTP_LIBRARY_SDIST_ROOT/examples/02_fail_closed_evaluation_outcomes.py"
PYTHONPATH= "$KTP_LIBRARY_ARTIFACT_ROOT/venv/bin/python" \
  "$KTP_LIBRARY_SDIST_ROOT/examples/03_observations_from_application_apis.py"
```

The examples must resolve the installed wheel and only their sdist-local
`_support` module. Record their full outputs, the ten supported base/crypto
suite results, all five provider results, all five catalogue checks, reviewed SHA,
archive SHA-256 values, inventories, metadata checks, boundary/stale-interface
scans, and final clean status. Keep intentional negative assertions visible;
inventory and allow only their exact lines during stale-name scans.

If verification reveals a defect, fix and commit it, freeze the new clean SHA,
then repeat the build, inventory, installation, examples, and final scans using
the new deterministic directory. Do not reuse evidence from the earlier SHA.

Repository visibility remains unchanged. Tagging, pushing, package publishing,
and GitHub release creation require a separately approved action. This
procedure and its automation establish neither application conformance nor
release approval. Service publication begins only after Library publication
and fresh-install verification.
