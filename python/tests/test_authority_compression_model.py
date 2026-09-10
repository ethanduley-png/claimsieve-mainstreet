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


def verify(certificate: Certificate, candidate: Candidate) -> bool:
    return (
        certificate.authorized
        and not certificate.revoked
        and not certificate.consumed
        and certificate.action == candidate.action
        and certificate.policy == candidate.policy
        and certificate.identity == candidate.identity
        and certificate.valid_from <= candidate.sequence <= certificate.expires_at
    )


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


if __name__ == "__main__":
    unittest.main()
