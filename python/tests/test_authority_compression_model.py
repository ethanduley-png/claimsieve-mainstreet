from dataclasses import dataclass, replace
from itertools import product
import unittest


@dataclass(frozen=True)
class Archive:
    action: int
    policy: int
    identity: int
    evidence: int
    authorized: bool
    payload: tuple[int, ...] = ()


@dataclass(frozen=True)
class Certificate:
    action: int
    policy: int
    identity: int
    evidence: int
    authorized: bool
    revoked: bool
    consumed: bool
    valid_from: int
    expires_at: int


@dataclass(frozen=True)
class Candidate:
    action: int
    policy: int
    identity: int
    sequence: int


def compress(archive: Archive, valid_from: int, expires_at: int) -> Certificate:
    return Certificate(
        archive.action,
        archive.policy,
        archive.identity,
        archive.evidence,
        archive.authorized,
        False,
        False,
        valid_from,
        expires_at,
    )


def guard_checks(certificate: Certificate, candidate: Candidate) -> dict[str, bool]:
    return {
        "authority": certificate.authorized,
        "revocation": not certificate.revoked,
        "consumption": not certificate.consumed,
        "action": certificate.action == candidate.action,
        "policy": certificate.policy == candidate.policy,
        "identity": certificate.identity == candidate.identity,
        "not_before": certificate.valid_from <= candidate.sequence,
        "expiry": candidate.sequence <= certificate.expires_at,
    }


def verify(certificate: Certificate, candidate: Candidate) -> bool:
    return all(guard_checks(certificate, candidate).values())


def verify_without_guard(
    certificate: Certificate, candidate: Candidate, omitted_guard: str
) -> bool:
    checks = guard_checks(certificate, candidate)
    if omitted_guard not in checks:
        raise ValueError(f"unknown runtime guard: {omitted_guard}")
    del checks[omitted_guard]
    return all(checks.values())


def verify_authenticated(
    certificate: Certificate, candidate: Candidate, signature_valid: bool
) -> bool:
    return signature_valid and verify(certificate, candidate)


class AuthorityCompressionModelTests(unittest.TestCase):
    def test_exhaustive_core_invariants(self) -> None:
        checked = 0
        for authorized, revoked, consumed in product((False, True), repeat=3):
            for values in product(range(2), repeat=6):
                cert_action, cert_policy, cert_identity, action, policy, identity = values
                for valid_from, expires_at, sequence in product(range(3), repeat=3):
                    certificate = Certificate(
                        cert_action,
                        cert_policy,
                        cert_identity,
                        9,
                        authorized,
                        revoked,
                        consumed,
                        valid_from,
                        expires_at,
                    )
                    candidate = Candidate(action, policy, identity, sequence)
                    accepted = verify(certificate, candidate)
                    checked += 1

                    if accepted:
                        self.assertTrue(authorized)
                        self.assertFalse(revoked)
                        self.assertFalse(consumed)
                        self.assertEqual(cert_action, action)
                        self.assertEqual(cert_policy, policy)
                        self.assertEqual(cert_identity, identity)
                        self.assertLessEqual(valid_from, sequence)
                        self.assertLessEqual(sequence, expires_at)

                    if not authorized or revoked or consumed:
                        self.assertFalse(accepted)
                    if cert_action != action or cert_policy != policy or cert_identity != identity:
                        self.assertFalse(accepted)
                    if sequence < valid_from or expires_at < sequence:
                        self.assertFalse(accepted)

        self.assertEqual(checked, 13_824)

    def test_compression_soundness_and_reconstruction(self) -> None:
        for authorized, action, policy, identity, evidence in product(
            (False, True), range(2), range(2), range(2), range(2)
        ):
            archive = Archive(
                action,
                policy,
                identity,
                evidence,
                authorized,
                payload=tuple(range(100)),
            )
            certificate = compress(archive, 1, 3)
            candidate = Candidate(action, policy, identity, 2)

            self.assertEqual(certificate.evidence, archive.evidence)
            self.assertEqual(certificate.authorized, archive.authorized)
            if verify(certificate, candidate):
                self.assertTrue(archive.authorized)

    def test_archived_payload_is_outside_fast_path(self) -> None:
        left = Archive(1, 2, 3, 4, True, payload=(1,))
        right = Archive(1, 2, 3, 4, True, payload=tuple(range(10_000)))
        candidate = Candidate(1, 2, 3, 5)

        self.assertEqual(compress(left, 0, 10), compress(right, 0, 10))
        self.assertEqual(
            verify(compress(left, 0, 10), candidate),
            verify(compress(right, 0, 10), candidate),
        )

    def test_each_guard_can_independently_block(self) -> None:
        base = Certificate(1, 2, 3, 4, True, False, False, 1, 3)
        good = Candidate(1, 2, 3, 2)

        self.assertTrue(verify(base, good))
        self.assertFalse(verify(replace(base, authorized=False), good))
        self.assertFalse(verify(replace(base, revoked=True), good))
        self.assertFalse(verify(replace(base, consumed=True), good))
        self.assertFalse(verify(base, replace(good, action=0)))
        self.assertFalse(verify(base, replace(good, policy=0)))
        self.assertFalse(verify(base, replace(good, identity=0)))
        self.assertFalse(verify(base, replace(good, sequence=0)))
        self.assertFalse(verify(base, replace(good, sequence=4)))

    def test_each_runtime_guard_is_pointwise_necessary(self) -> None:
        base = Certificate(1, 2, 3, 4, True, False, False, 10, 20)
        good = Candidate(1, 2, 3, 15)
        omission_witnesses = {
            "authority": (replace(base, authorized=False), good),
            "revocation": (replace(base, revoked=True), good),
            "consumption": (replace(base, consumed=True), good),
            "action": (base, replace(good, action=9)),
            "policy": (base, replace(good, policy=9)),
            "identity": (base, replace(good, identity=9)),
            "not_before": (base, replace(good, sequence=9)),
            "expiry": (base, replace(good, sequence=21)),
        }

        for guard, (certificate, candidate) in omission_witnesses.items():
            with self.subTest(guard=guard):
                self.assertFalse(verify(certificate, candidate))
                self.assertTrue(verify_without_guard(certificate, candidate, guard))

    def test_exhaustive_guard_omission_matrix(self) -> None:
        unsafe_accepts = {
            "authority": 0,
            "revocation": 0,
            "consumption": 0,
            "action": 0,
            "policy": 0,
            "identity": 0,
            "not_before": 0,
            "expiry": 0,
        }
        full_accepts = 0
        checked = 0

        for authorized, revoked, consumed in product((False, True), repeat=3):
            for values in product(range(2), repeat=6):
                cert_action, cert_policy, cert_identity, action, policy, identity = values
                for valid_from, expires_at, sequence in product(range(3), repeat=3):
                    certificate = Certificate(
                        cert_action,
                        cert_policy,
                        cert_identity,
                        9,
                        authorized,
                        revoked,
                        consumed,
                        valid_from,
                        expires_at,
                    )
                    candidate = Candidate(action, policy, identity, sequence)
                    full = verify(certificate, candidate)
                    checked += 1
                    full_accepts += int(full)

                    for guard in unsafe_accepts:
                        weakened = verify_without_guard(certificate, candidate, guard)
                        if weakened and not full:
                            unsafe_accepts[guard] += 1

        self.assertEqual(checked, 13_824)
        self.assertEqual(full_accepts, 80)
        self.assertEqual(
            unsafe_accepts,
            {
                "authority": 80,
                "revocation": 80,
                "consumption": 80,
                "action": 80,
                "policy": 80,
                "identity": 80,
                "not_before": 64,
                "expiry": 64,
            },
        )

    def test_certificate_authenticity_is_outer_guard(self) -> None:
        certificate = Certificate(1, 2, 3, 4, True, False, False, 10, 20)
        candidate = Candidate(1, 2, 3, 15)

        self.assertTrue(verify(certificate, candidate))
        self.assertTrue(verify_authenticated(certificate, candidate, True))
        self.assertFalse(verify_authenticated(certificate, candidate, False))

    def test_evidence_digest_is_archive_link_not_runtime_guard(self) -> None:
        candidate = Candidate(1, 2, 3, 15)
        left = Certificate(1, 2, 3, 4, True, False, False, 10, 20)
        right = replace(left, evidence=999_999)

        self.assertNotEqual(left.evidence, right.evidence)
        self.assertEqual(verify(left, candidate), verify(right, candidate))
        self.assertTrue(verify(left, candidate))


if __name__ == "__main__":
    unittest.main()
