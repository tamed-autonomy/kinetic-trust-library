from kinetic_trust_library import EvaluationBundle, EvaluationRequest
from kinetic_trust_library.core import evaluate

from _support import (
    CUTOFF,
    OPERATION_ID,
    build_observations,
    build_profile,
    build_soul_responses,
    build_standing,
    build_validated_action,
)


def main() -> None:
    profile = build_profile()
    action = build_validated_action(profile)
    request = EvaluationRequest(
        operation_id=OPERATION_ID,
        profile=profile,
        action=action,
        standing=build_standing(),
        observations=build_observations(),
        soul_responses=build_soul_responses(profile, action),
        cutoff=CUTOFF,
    )
    outcome = evaluate(request)
    if type(outcome) is not EvaluationBundle:
        raise RuntimeError(
            f"example request rejected at {outcome.failed_stage.value}: {outcome.rationale[0]}"
        )
    if outcome.risk is None or outcome.trust is None or outcome.core_capacity is None:
        raise RuntimeError("CLEAR example did not complete risk and trust")
    print("result_type=EvaluationBundle")
    print(f"risk={outcome.risk.risk}")
    print(f"E_base={outcome.trust.base_trust}")
    print(f"E_trust={outcome.trust.effective_trust}")
    print(f"tier={outcome.trust.tier.value}")
    print(f"capacity_relation={outcome.core_capacity.relation.value}")
    print(f"within_capacity={outcome.core_capacity.within_capacity}")
    print(f"envelope_capacity={outcome.envelope.environmental_capacity}")
    print(f"envelope_margin={outcome.envelope.margin}")
    print(f"envelope_supervision={outcome.envelope.supervision.value}")
    print(
        "constraints="
        + ",".join(
            f"{item.magnitude}:{item.maximum}:{item.unit}"
            for item in outcome.envelope.tightened_constraints.ceilings
        )
    )
    print("action_executed=false")


if __name__ == "__main__":
    main()
