from dataclasses import dataclass
from itertools import product
import unittest


@dataclass(frozen=True)
class Certificate:
    authorized: bool
    action_digest: int
    policy_digest: int
    identity_digest: int
    evidence_digest: int
    valid_from: int
    expires_at: int


@dataclass(frozen=True)
class Archive:
    action_digest: int
    policy_digest: int
    identity_digest: int
    evidence_digest: int
    reconstructs_allow: bool


@dataclass(frozen=True)
class Candidate:
    action_digest: int
    policy_digest: int
    identity_digest: int
    sequence: int


@dataclass(frozen=True)
class CurrentState:
    policy_digest: int
    identity_digest: int
    policy_active: bool
    identity_active: bool
    campaign_active: bool
    execution_frozen: bool
    campaign_suspended: bool
    permit_revoked: bool
    permit_consumed: bool


@dataclass(frozen=True)
class PersistedAuthority:
    authority_id: int
    certificate: Certificate
    archive: Archive


def verify_compact(certificate: Certificate, candidate: Candidate) -> bool:
    return (
        certificate.authorized
        and certificate.action_digest == candidate.action_digest
        and certificate.policy_digest == candidate.policy_digest
        and certificate.identity_digest == candidate.identity_digest
        and certificate.valid_from <= candidate.sequence <= certificate.expires_at
    )


def current_state_allows(certificate: Certificate, current: CurrentState) -> bool:
    return (
        certificate.policy_digest == current.policy_digest
        and certificate.identity_digest == current.identity_digest
        and current.policy_active
        and current.identity_active
        and current.campaign_active
        and not current.execution_frozen
        and not current.campaign_suspended
        and not current.permit_revoked
        and not current.permit_consumed
    )


def executable_now(
    entry: PersistedAuthority, candidate: Candidate, current: CurrentState
) -> bool:
    return verify_compact(entry.certificate, candidate) and current_state_allows(
        entry.certificate, current
    )


def lineage_valid(entry: PersistedAuthority) -> bool:
    certificate = entry.certificate
    archive = entry.archive
    return (
        certificate.action_digest == archive.action_digest
        and certificate.policy_digest == archive.policy_digest
        and certificate.identity_digest == archive.identity_digest
        and certificate.evidence_digest == archive.evidence_digest
        and certificate.authorized == archive.reconstructs_allow
    )


def lookup(store: tuple[PersistedAuthority, ...], authority_id: int):
    return next((entry for entry in store if entry.authority_id == authority_id), None)


def reconstruct_from_store(
    store: tuple[PersistedAuthority, ...], authority_id: int
):
    entry = lookup(store, authority_id)
    return None if entry is None else entry.archive.reconstructs_allow


def base_entry() -> PersistedAuthority:
    certificate = Certificate(True, 11, 22, 33, 44, 10, 15)
    archive = Archive(11, 22, 33, 44, True)
    return PersistedAuthority(7, certificate, archive)


def base_candidate() -> Candidate:
    return Candidate(11, 22, 33, 12)


def base_current() -> CurrentState:
    return CurrentState(22, 33, True, True, True, False, False, False, False)


class ExecutionAuthorityReconstructionModelTests(unittest.TestCase):
    def test_valid_execution_is_prior_exact_and_reconstructable(self) -> None:
        entry = base_entry()
        candidate = base_candidate()
        current = base_current()
        store = (entry,)

        self.assertTrue(lineage_valid(entry))
        self.assertTrue(executable_now(entry, candidate, current))
        self.assertIs(reconstruct_from_store(store, entry.authority_id), True)
        self.assertEqual(entry.certificate.action_digest, candidate.action_digest)
        self.assertEqual(entry.certificate.policy_digest, candidate.policy_digest)
        self.assertEqual(entry.certificate.identity_digest, candidate.identity_digest)
        self.assertEqual(entry.certificate.evidence_digest, entry.archive.evidence_digest)

    def test_missing_archive_is_not_reconstructable(self) -> None:
        self.assertIsNone(reconstruct_from_store(tuple(), 7))

    def test_authority_relevant_mutations_fail_closed(self) -> None:
        entry = base_entry()
        current = base_current()
        candidates = (
            Candidate(99, 22, 33, 12),
            Candidate(11, 99, 33, 12),
            Candidate(11, 22, 99, 12),
            Candidate(11, 22, 33, 9),
            Candidate(11, 22, 33, 16),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                self.assertFalse(executable_now(entry, candidate, current))

    def test_archive_evidence_mutation_breaks_lineage_without_hot_path_change(self) -> None:
        entry = base_entry()
        mutated = PersistedAuthority(
            entry.authority_id,
            entry.certificate,
            Archive(11, 22, 33, 999, True),
        )

        self.assertTrue(executable_now(mutated, base_candidate(), base_current()))
        self.assertFalse(lineage_valid(mutated))

    def test_unauthorized_archive_cannot_support_valid_lineage_and_execution(self) -> None:
        certificate = Certificate(True, 11, 22, 33, 44, 10, 15)
        archive = Archive(11, 22, 33, 44, False)
        entry = PersistedAuthority(7, certificate, archive)

        self.assertTrue(executable_now(entry, base_candidate(), base_current()))
        self.assertFalse(lineage_valid(entry))

    def test_exhaustive_invariant_no_counterexample(self) -> None:
        checked = 0
        qualifying = 0
        violations = 0

        for bits in product((False, True), repeat=14):
            (
                authorized,
                reconstructs_allow,
                candidate_action_matches,
                candidate_policy_matches,
                candidate_identity_matches,
                archive_action_matches,
                archive_policy_matches,
                archive_identity_matches,
                archive_evidence_matches,
                policy_active,
                identity_active,
                campaign_active,
                execution_frozen,
                revoked,
            ) = bits

            certificate = Certificate(authorized, 11, 22, 33, 44, 10, 15)
            archive = Archive(
                11 if archive_action_matches else 101,
                22 if archive_policy_matches else 202,
                33 if archive_identity_matches else 303,
                44 if archive_evidence_matches else 404,
                reconstructs_allow,
            )
            entry = PersistedAuthority(7, certificate, archive)
            candidate = Candidate(
                11 if candidate_action_matches else 111,
                22 if candidate_policy_matches else 222,
                33 if candidate_identity_matches else 333,
                12,
            )
            current = CurrentState(
                22,
                33,
                policy_active,
                identity_active,
                campaign_active,
                execution_frozen,
                False,
                revoked,
                False,
            )
            store = (entry,)
            checked += 1

            if lineage_valid(entry) and executable_now(entry, candidate, current):
                qualifying += 1
                invariant = (
                    reconstruct_from_store(store, 7) is True
                    and certificate.action_digest == candidate.action_digest
                    and certificate.policy_digest == candidate.policy_digest
                    and certificate.identity_digest == candidate.identity_digest
                    and certificate.evidence_digest == archive.evidence_digest
                )
                if not invariant:
                    violations += 1

        self.assertEqual(checked, 16_384)
        self.assertGreater(qualifying, 0)
        self.assertEqual(violations, 0)


if __name__ == "__main__":
    unittest.main()
