#!/usr/bin/env python3
"""Regression: Taproot control-block parity must match coincurve; v1 removed."""
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from coincurve import PrivateKey, PublicKey
from embit import ec

from dlc_builder import build_dlc
from dlc_builder.taproot import tagged_hash
from lending_dlc_builder import build_collateral_dlc


def main() -> int:
    odd = 0
    for _ in range(40):
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
        assert desc.output_key_parity == Q[0] - 2
        assert (bytes.fromhex(desc.claim_control_block)[0] & 1) == (Q[0] - 2)
        if desc.output_key_parity:
            odd += 1
    assert odd > 0

    try:
        build_collateral_dlc(
            adaptor_point_hex=ec.PrivateKey(secrets.token_bytes(32)).get_public_key().serialize().hex(),
            borrower_pubkey_hex=recv,
            lender_pubkey_hex=send,
            oracle_pubkey_hex=recv,
            safety_timeout=900_000,
            protocol_version=1,
        )
        raise SystemExit("v1 must be rejected")
    except ValueError:
        pass

    print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
