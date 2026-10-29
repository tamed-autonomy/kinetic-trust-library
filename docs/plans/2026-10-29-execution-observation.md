# Execution observation implementation plan

> Execute inline with the existing execution/TDD/verification workflow.

Goal: implement Core §7.6 and Audit §3.4 at RFC commit
`151cfe46e447be68794dfadf8bf11cfde79110d1`, preserving all three EO vectors.

Architecture: immutable semantic operation/decision/observation bindings and a
pure classifier in `v3/execution_observation.py`; an installed Source wrapper
in `v3/installed_execution_observation.py` authenticates historical decisions,
actual boundary facts and completeness/absence for the exact operation. These
are private adapter projections, not invented audit wire records. Dispatch is
observed execution in the EO vocabulary, never confirmed downstream effect in
the optional #139 contract. No observation means unverified, never non-dispatch.

Source owns actual signature/record/observer authority and route enforcement
truth. Library binds actual actor, complete operation digest, zone/epoch,
decision digest/identity and observation time; a mismatched observation supplies
no execution claim. A known no-decision route with no enforcement point and
observed dispatch is a bypass. Denial plus bound dispatch is also a bypass,
including denial by an independent required gate. Return an obligation to record
a conformance failure/open a breach, not a false claim that either was persisted.

- [x] Retain exact EO source cases and test pure classification/binding/direction.
- [x] Implement the pure immutable model and classifier; verify focused tests.
- [x] Test and implement the installed exact current Source/profile/time wrapper,
      with evidence retained and substitutions/unverified states rejected.
- [x] Supplier review, full regression and built-package checks; document scope
      and update traceability. Full suite: 1,039 tests; built-package focus: 14.
      Checkpoint this work on the existing development branch and push; no PR,
      merge, version cutover or release.

Retained source suite SHA-256:
`802561f258902b5741dc89b22cb707a56ef00a9869e781a333e3bedd79727871`.

Continue broader L11/person/hand-back/optional/full-deployment work afterwards;
this contract does not discharge those requirements.
