"""Collateral DLC tests: NUMS internal key, validation, no v1 path."""
import secrets
import sys

from embit import ec

from lending_dlc_builder import build_collateral_dlc
from lending_dlc_builder.lending_scripts import build_lending_v2_repay_script


def _xonly_hex() -> str:
    return ec.PrivateKey(secrets.token_bytes(32)).get_public_key().xonly().hex()


def _compressed_hex() -> str:
    return ec.PrivateKey(secrets.token_bytes(32)).get_public_key().serialize().hex()


def test_v2_repay_script_shape():
    key = bytes.fromhex(_xonly_hex())
    v2 = build_lending_v2_repay_script(key)
    assert len(v2) == 34
    assert v2.endswith(bytes([0xAC]))  # OP_CHECKSIG


def test_v2_collateral_descriptor():
    desc = build_collateral_dlc(
        adaptor_point_hex=_compressed_hex(),
        borrower_pubkey_hex=_xonly_hex(),
        lender_pubkey_hex=_xonly_hex(),
        oracle_pubkey_hex=_xonly_hex(),
        safety_timeout=900_000,
        network="mainnet",
        protocol_version=2,
        repay_pubkey_hex=_xonly_hex(),
    )
    assert desc.internal_private_key is None
    assert desc.address.startswith("bc1p")
    assert bytes.fromhex(desc.repay_control_block)[0] in (0xC0, 0xC1)
    repay_bytes = bytes.fromhex(desc.repay_script)
    assert repay_bytes == build_lending_v2_repay_script(bytes.fromhex(desc.repay_pubkey))


def test_v1_rejected():
    try:
        build_collateral_dlc(
            adaptor_point_hex=_compressed_hex(),
            borrower_pubkey_hex=_xonly_hex(),
            lender_pubkey_hex=_xonly_hex(),
            oracle_pubkey_hex=_xonly_hex(),
            safety_timeout=900_000,
            protocol_version=1,
        )
        raise AssertionError("protocol_version=1 must raise")
    except ValueError as e:
        assert "removed" in str(e).lower() or "protocol_version" in str(e)


def test_safety_timeout_zero_rejected():
    try:
        build_collateral_dlc(
            adaptor_point_hex=_compressed_hex(),
            borrower_pubkey_hex=_xonly_hex(),
            lender_pubkey_hex=_xonly_hex(),
            oracle_pubkey_hex=_xonly_hex(),
            safety_timeout=0,
        )
        raise AssertionError("safety_timeout=0 must raise")
    except ValueError:
        pass


def test_fixed_term_gap_enforced():
    try:
        build_collateral_dlc(
            adaptor_point_hex=_compressed_hex(),
            borrower_pubkey_hex=_xonly_hex(),
            lender_pubkey_hex=_xonly_hex(),
            safety_timeout=900_000,
            attestation_mode="fixed_term",
            lender_claim_cltv_height=899_900,  # gap 100 < 144
        )
        raise AssertionError("insufficient safety gap must raise")
    except ValueError:
        pass


def test_oracle_pubkey_required():
    try:
        build_collateral_dlc(
            adaptor_point_hex=_compressed_hex(),
            borrower_pubkey_hex=_xonly_hex(),
            lender_pubkey_hex=_xonly_hex(),
            oracle_pubkey_hex="",
            safety_timeout=900_000,
            attestation_mode="oracle",
        )
        raise AssertionError("empty oracle must raise")
    except ValueError:
        pass


def test_collateral_parity_matches_coincurve():
    from coincurve import PrivateKey, PublicKey
    from dlc_builder.taproot import tagged_hash

    odd = 0
    for _ in range(40):
        desc = build_collateral_dlc(
            adaptor_point_hex=_compressed_hex(),
            borrower_pubkey_hex=_xonly_hex(),
            lender_pubkey_hex=_xonly_hex(),
            oracle_pubkey_hex=_xonly_hex(),
            safety_timeout=900_000,
            repay_pubkey_hex=_xonly_hex(),
        )
        ipk = bytes.fromhex(desc.internal_pubkey)
        mr = bytes.fromhex(desc.merkle_root)
        tweak = tagged_hash("TapTweak", ipk + mr)
        Q = PublicKey.combine_keys(
            [PublicKey(b"\x02" + ipk), PrivateKey(tweak).public_key]
        ).format(compressed=True)
        assert desc.output_key_parity == Q[0] - 2
        assert (bytes.fromhex(desc.repay_control_block)[0] & 1) == (Q[0] - 2)
        if desc.output_key_parity == 1:
            odd += 1
    assert odd > 0


if __name__ == "__main__":
    test_v2_repay_script_shape()
    test_v2_collateral_descriptor()
    test_v1_rejected()
    test_safety_timeout_zero_rejected()
    test_fixed_term_gap_enforced()
    test_oracle_pubkey_required()
    test_collateral_parity_matches_coincurve()
    print("ok")
    sys.exit(0)
