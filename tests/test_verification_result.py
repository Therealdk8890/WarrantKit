import pytest

from agentcontain.verification_result import (
    VerificationResult,
    VerificationStatus,
    compose_verification,
)


def _complete_result(**overrides: object) -> VerificationResult:
    values: dict[str, object] = {
        "authority_valid": True,
        "runtime_valid": True,
        "authenticated": True,
        "correlated": True,
        "anchored": True,
        "verifier_executed": True,
    }
    values.update(overrides)
    return compose_verification(**values)  # type: ignore[arg-type]


def test_complete_result_is_verified() -> None:
    result = _complete_result()
    assert result.status == VerificationStatus.VERIFIED
    assert result.is_verified is True


def test_missing_anchor_is_incomplete() -> None:
    result = _complete_result(anchored=False, missing=("external anchor",))
    assert result.status == VerificationStatus.INCOMPLETE
    assert result.is_verified is False


def test_conflict_dominates_other_successes() -> None:
    result = _complete_result(conflicts=("external artifact differs from anchor",))
    assert result.status == VerificationStatus.CONFLICT


def test_unauthenticated_cannot_be_verified() -> None:
    result = _complete_result(authenticated=False)
    assert result.status == VerificationStatus.UNAUTHENTICATED
    assert result.is_verified is False


def test_verification_does_not_create_authority_or_truth() -> None:
    result = _complete_result()
    assert result.is_authorized is False
    assert result.claim_is_true is False


def test_missing_evidence_never_defaults_to_success() -> None:
    result = _complete_result(verifier_executed=False, missing=("verification procedure",))
    assert result.status == VerificationStatus.INCOMPLETE


def test_serialization_preserves_each_dimension() -> None:
    result = _complete_result(
        runtime_valid=False,
        correlated=False,
        anchored=False,
        verifier_executed=False,
        missing=("runtime proof", "anchor"),
    )
    document = result.to_dict()
    assert document["authority_valid"] is True
    assert document["runtime_valid"] is False
    assert document["authenticated"] is True
    assert document["correlated"] is False
    assert document["anchored"] is False
    assert document["verifier_executed"] is False
    assert document["status"] == "incomplete"


@pytest.mark.parametrize("field", [
    "authority_valid",
    "runtime_valid",
    "authenticated",
    "correlated",
    "anchored",
    "verifier_executed",
])
@pytest.mark.parametrize("invalid", ["false", 1, 0, None, [], {}])
def test_check_dimensions_reject_non_booleans(field: str, invalid: object) -> None:
    with pytest.raises(TypeError, match=f"{field} must be a bool"):
        _complete_result(**{field: invalid})


@pytest.mark.parametrize("field", ["conflicts", "missing"])
@pytest.mark.parametrize("invalid", ["not-a-sequence", None, 7, {}])
def test_diagnostic_fields_require_sequences(field: str, invalid: object) -> None:
    with pytest.raises(TypeError, match=f"{field} must be a tuple or list"):
        _complete_result(**{field: invalid})


@pytest.mark.parametrize("field", ["conflicts", "missing"])
@pytest.mark.parametrize("invalid", [("",), ("  ",), (None,), (False,), (3,)])
def test_diagnostic_fields_reject_empty_or_non_string_items(field: str, invalid: object) -> None:
    with pytest.raises(ValueError, match=f"{field} must contain only non-empty strings"):
        _complete_result(**{field: invalid})


def test_diagnostic_lists_are_normalized_to_tuples() -> None:
    result = _complete_result(conflicts=["collision"])
    assert result.conflicts == ("collision",)
