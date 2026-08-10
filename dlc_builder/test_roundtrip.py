"""Smoke + adversarial tests for adaptor math and Taproot spendability metadata."""
import secrets
import sys

from dlc_builder import (
    adaptor_complete,
    adaptor_extract,
    adaptor_presign,
    adaptor_verify,
    build_dlc,
    point_from_secret,
    pubkey_xonly,
    schnorr_verify,
)
from dlc_builder.taproot import tagged_hash, taproot_tweak_pubkey


def test_adaptor_roundtrip():
    d = secrets.token_bytes(32)
    t = secrets.token_bytes(32)
    msg = secrets.token_bytes(32)
    p = pubkey_xonly(d)
    T = point_from_secret(t)
    assert len(T) == 33
    presig = adaptor_presign(d, msg, T)
    assert adaptor_verify(p, msg, presig, T)
    full = adaptor_complete(presig, t)
    assert schnorr_verify(p, msg, full)
    assert adaptor_extract(presig, full, T) == t


def test_adaptor_rejects_xonly_T():
    d = secrets.token_bytes(32)
    t = secrets.token_bytes(32)
    msg = secrets.token_bytes(32)
    T = point_from_secret(t)
    try:
        adaptor_presign(d, msg, T[1:])
        raise AssertionError("expected ValueError for 32-byte T")
    except ValueError:
        pass
    presig = adaptor_presign(d, msg, T)
    full = adaptor_complete(presig, t)
    assert adaptor_extract(presig, full, T[1:]) is None


def test_build_descriptor():
    from embit import ec

    receiver_x = ec.PrivateKey(secrets.token_bytes(32)).get_public_key().xonly().hex()
    sender_x = ec.PrivateKey(secrets.token_bytes(32)).get_public_key().xonly().hex()
    desc = build_dlc(
        receiver_pubkey_hex=receiver_x,
        sender_pubkey_hex=sender_x,
        timeout=900_000,
        network="mainnet",
    )
    assert desc.address.startswith("bc1p")
    assert len(desc.claim_script) > 0
    assert bytes.fromhex(desc.claim_control_block)[0] in (0xC0, 0xC1)


def test_control_block_parity_matches_coincurve():
    """Regression: embit taproot_tweak always reported parity=0 (fund-loss bug)."""
    from coincurve import PrivateKey, PublicKey
    from embit import ec

    odd_parity_seen = False
    for _ in range(80):
        recv = ec.PrivateKey(secrets.token_bytes(32)).get_public_key().xonly().hex()
        send = ec.PrivateKey(secrets.token_bytes(32)).get_public_key().xonly().hex()
        desc = build_dlc(
            receiver_pubkey_hex=recv,
            sender_pubkey_hex=send,
            timeout=900_000,
            network="mainnet",
        )
        ipk = bytes.fromhex(desc.internal_pubkey)
        mr = bytes.fromhex(desc.merkle_root)
        tweak = tagged_hash("TapTweak", ipk + mr)
        Q = PublicKey.combine_keys(
            [PublicKey(b"\x02" + ipk), PrivateKey(tweak).public_key]
        ).format(compressed=True)
        true_parity = Q[0] - 2
        assert desc.output_key_parity == true_parity
        assert (bytes.fromhex(desc.claim_control_block)[0] & 1) == true_parity
        assert (bytes.fromhex(desc.refund_control_block)[0] & 1) == true_parity
        assert Q[1:].hex() == desc.output_pubkey
        if true_parity == 1:
            odd_parity_seen = True
    assert odd_parity_seen, "expected at least one odd-parity descriptor in sample"


def test_taproot_tweak_pubkey_not_always_even():
    from coincurve import PrivateKey

    odds = 0
    for _ in range(40):
        ipk = PrivateKey(secrets.token_bytes(32)).public_key.format(compressed=True)[1:]
        mr = secrets.token_bytes(32)
        _, parity = taproot_tweak_pubkey(ipk, mr)
        if parity == 1:
            odds += 1
    assert odds > 0, "taproot_tweak_pubkey must not always return parity=0"


def test_nums_internal_golden():
    """Pin internal-key domain tag + NUMS construction for fixed inputs."""
    from embit import ec

    recv = ec.PrivateKey(bytes.fromhex("11" * 32)).get_public_key().xonly().hex()
    send = ec.PrivateKey(bytes.fromhex("22" * 32)).get_public_key().xonly().hex()
    desc = build_dlc(
        receiver_pubkey_hex=recv,
        sender_pubkey_hex=send,
        timeout=850_000,
        network="mainnet",
    )
    assert (
        desc.internal_pubkey
        == "7b62b5963b2025adc5fd9f103b18daf42fdd67573eb3d68b7dbec228a00b49c7"
    )
    assert desc.address == "bc1p6c3ztgq6rwasu9ljt0pzppy0k0me3w06rhw2s9l7dlygzdsacxvs4h3w80"


if __name__ == "__main__":
    test_adaptor_roundtrip()
    test_adaptor_rejects_xonly_T()
    test_build_descriptor()
    test_control_block_parity_matches_coincurve()
    test_taproot_tweak_pubkey_not_always_even()
    test_nums_internal_golden()
    print("ok")
    sys.exit(0)
