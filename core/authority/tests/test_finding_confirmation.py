from core.findings import (
    AuthorizedScope,
    FindingRegistry,
    Observation,
    confirm_finding,
    finding_fingerprint,
)


TARGET = "service://synthetic-api"


def observation(observation_id: str, *, status: int, role: str = "viewer") -> Observation:
    return Observation(
        observation_id=observation_id,
        target=TARGET,
        measurements={"response_status": status, "observed_role": role},
    )


def confirm(registry: FindingRegistry | None = None):
    return confirm_finding(
        scope=AuthorizedScope("scope-001", frozenset({TARGET})),
        target=TARGET,
        test_vector="authorization-boundary-check",
        baseline=observation("baseline", status=403),
        test_runs=(
            observation("test-1", status=200, role="admin"),
            observation("test-2", status=200, role="admin"),
        ),
        registry=registry or FindingRegistry(),
    )


def test_confirms_authorized_reproducible_difference_with_o0_receipt():
    result = confirm()

    assert result.status == "CONFIRMED"
    assert result.reason == "authorized_reproducible_difference"
    assert result.authority == "EVIDENCE_ONLY"
    assert result.operational_authority == "O0"
    assert len(result.receipt_hash) == 64
    assert result.differences == (
        ("observed_role", "viewer", "admin"),
        ("response_status", 403, 200),
    )


def test_rejects_target_outside_exact_authorized_scope():
    result = confirm_finding(
        scope=AuthorizedScope("scope-001", frozenset({"service://other"})),
        target=TARGET,
        test_vector="authorization-boundary-check",
        baseline=observation("baseline", status=403),
        test_runs=(observation("test-1", status=200), observation("test-2", status=200)),
        registry=FindingRegistry(),
    )

    assert result.status == "REJECTED"
    assert result.reason == "target_out_of_scope"


def test_rejects_a_single_test_run_as_not_reproduced():
    result = confirm_finding(
        scope=AuthorizedScope("scope-001", frozenset({TARGET})),
        target=TARGET,
        test_vector="authorization-boundary-check",
        baseline=observation("baseline", status=403),
        test_runs=(observation("test-1", status=200),),
        registry=FindingRegistry(),
    )

    assert result.status == "REJECTED"
    assert result.reason == "insufficient_reproduction_runs"


def test_rejects_when_comparison_has_no_measurable_difference():
    result = confirm_finding(
        scope=AuthorizedScope("scope-001", frozenset({TARGET})),
        target=TARGET,
        test_vector="authorization-boundary-check",
        baseline=observation("baseline", status=403),
        test_runs=(observation("test-1", status=403), observation("test-2", status=403)),
        registry=FindingRegistry(),
    )

    assert result.status == "REJECTED"
    assert result.reason == "no_measurable_difference"


def test_rejects_non_reproducible_differences():
    result = confirm_finding(
        scope=AuthorizedScope("scope-001", frozenset({TARGET})),
        target=TARGET,
        test_vector="authorization-boundary-check",
        baseline=observation("baseline", status=403),
        test_runs=(
            observation("test-1", status=200, role="admin"),
            observation("test-2", status=201, role="editor"),
        ),
        registry=FindingRegistry(),
    )

    assert result.status == "REJECTED"
    assert result.reason == "non_reproducible_difference"


def test_suppresses_duplicate_scope_target_vector():
    registry = FindingRegistry()

    first = confirm(registry)
    second = confirm(registry)

    assert first.status == "CONFIRMED"
    assert second.status == "DUPLICATE"
    assert second.reason == "duplicate_scope_target_vector"


def test_fingerprint_is_deterministic_and_scope_bound():
    first = finding_fingerprint("scope-001", TARGET, "vector-a")
    repeated = finding_fingerprint("scope-001", TARGET, "vector-a")
    different_scope = finding_fingerprint("scope-002", TARGET, "vector-a")

    assert first == repeated
    assert first != different_scope


def test_receipt_is_deterministic_and_binds_observation_digests():
    first = confirm()
    repeated = confirm()

    assert first.receipt_hash == repeated.receipt_hash
    assert first.baseline_digest
    assert len(first.test_run_digests) == 2
    assert first.test_run_digests[0] != first.test_run_digests[1]
