from dataclasses import replace

from kinetic_trust_library import EvaluationBundle, RejectedRequest
from kinetic_trust_library.core import evaluate

from _support import build_observations, build_request


def show_result(case: str, outcome: EvaluationBundle | RejectedRequest) -> None:
    print(f"case={case}")
    print(f"result_type={type(outcome).__name__}")
    if type(outcome) is RejectedRequest:
        print(f"failed_stage={outcome.failed_stage.value}")
        print("trace=" + ",".join(stage.value for stage in outcome.trace))
        return
    downstream_present = any(
        value is not None
        for value in (
            outcome.standing,
            outcome.evidence,
            outcome.risk,
            outcome.trust,
            outcome.velocity,
            outcome.core_capacity,
        )
    )
    print(f"soul={outcome.soul.state.value}")
    print(f"downstream_present={str(downstream_present).lower()}")
    if outcome.risk is not None:
        print(f"risk={outcome.risk.risk}")
        print(f"undefined_inputs={len(outcome.risk.undefined_inputs)}")
    if outcome.core_capacity is None:
        print("core_capacity=unevaluated")
    else:
        print(f"capacity_relation={outcome.core_capacity.relation.value}")
        print(f"within_capacity={outcome.core_capacity.within_capacity}")
    print(f"envelope_margin={outcome.envelope.margin}")
    print(f"envelope_supervision={outcome.envelope.supervision.value}")


def load_application_observations() -> tuple[object, ...]:
    raise RuntimeError("application evidence API unavailable")


def main() -> None:
    show_result("clear", evaluate(build_request()))
    show_result("soul_veto", evaluate(build_request(soul_state="veto")))
    show_result(
        "soul_undetermined",
        evaluate(build_request(soul_state="undetermined")),
    )
    show_result("missing_evidence", evaluate(build_request(observations=())))

    observations = build_observations()
    invalid = (replace(observations[0], unit="wrong-unit"), *observations[1:])
    show_result(
        "rejected_request",
        evaluate(build_request(observations=invalid)),
    )

    try:
        load_application_observations()
    except RuntimeError as error:
        print("case=application_failure")
        print(f"exception_type={type(error).__name__}")
        print("library_called=false")
        print("ktp_result=false")

    print("action_executed=false")


if __name__ == "__main__":
    main()
