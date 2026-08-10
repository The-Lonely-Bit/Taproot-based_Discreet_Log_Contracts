#!/usr/bin/env python3
"""
Smoke tests for taproot-dlc-lab builders.

Optional interop checks load ./Signer/signer.py (or ../psbt-signer/signer.py).

  export PYTHONPATH=.
  python3 test_opensource_stack.py
"""
from __future__ import annotations

import importlib.util
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
_SIGNER_CANDIDATES = (
    ROOT / "Signer" / "signer.py",
    ROOT.parent / "psbt-signer" / "signer.py",
)
SIGNER_PATH = next((p for p in _SIGNER_CANDIDATES if p.is_file()), _SIGNER_CANDIDATES[0])
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PASS = 0
FAIL = 0


def ok(name: str) -> None:
    global PASS
    PASS += 1
    print(f"  PASS  {name}")


def fail(name: str, err: Exception) -> None:
    global FAIL
    FAIL += 1
    print(f"  FAIL  {name}: {err}")


def run(name: str, fn) -> None:
    try:
        fn()
        ok(name)
    except Exception as e:
        fail(name, e)


def test_dlc_adaptor_roundtrip():
    from dlc_builder import (
        adaptor_complete,
        adaptor_extract,
        adaptor_presign,
        adaptor_verify,
        point_from_secret,
        pubkey_xonly,
        schnorr_verify,
    )

    d = secrets.token_bytes(32)
    t = secrets.token_bytes(32)
    msg = secrets.token_bytes(32)
    p = pubkey_xonly(d)
    T = point_from_secret(t)
    presig = adaptor_presign(d, msg, T)
    assert adaptor_verify(p, msg, presig, T)
    full = adaptor_complete(presig, t)
    assert schnorr_verify(p, msg, full)
    assert adaptor_extract(presig, full, T) == t


def test_dlc_build_multi_network():
    from embit import ec

    from dlc_builder import build_dlc

    recv = ec.PrivateKey(secrets.token_bytes(32)).get_public_key().xonly().hex()
    send = ec.PrivateKey(secrets.token_bytes(32)).get_public_key().xonly().hex()
    for net, prefix in [("mainnet", "bc1p"), ("litecoin", "ltc1p")]:
        desc = build_dlc(
            receiver_pubkey_hex=recv,
            sender_pubkey_hex=send,
            timeout=900_000,
            network=net,
        )
        assert desc.address.startswith(prefix)
        assert len(desc.claim_script) > 0
        assert bytes.fromhex(desc.claim_control_block)[0] in (0xC0, 0xC1)
    desc_fb = build_dlc(
        receiver_pubkey_hex=recv,
        sender_pubkey_hex=send,
        timeout=900_000,
        hrp="fb",
    )
    assert desc_fb.address.startswith("fb1p")


def test_dlc_parity_regression():
    from coincurve import PrivateKey, PublicKey
    from embit import ec

    from dlc_builder import build_dlc
    from dlc_builder.taproot import tagged_hash

    odd = 0
    for _ in range(40):
        desc = build_dlc(
            receiver_pubkey_hex=ec.PrivateKey(secrets.token_bytes(32))
            .get_public_key()
            .xonly()
            .hex(),
            sender_pubkey_hex=ec.PrivateKey(secrets.token_bytes(32))
            .get_public_key()
            .xonly()
            .hex(),
            timeout=900_000,
        )
        ipk = bytes.fromhex(desc.internal_pubkey)
        mr = bytes.fromhex(desc.merkle_root)
        tweak = tagged_hash("TapTweak", ipk + mr)
        Q = PublicKey.combine_keys(
            [PublicKey(b"\x02" + ipk), PrivateKey(tweak).public_key]
        ).format(compressed=True)
        assert desc.output_key_parity == Q[0] - 2
        if desc.output_key_parity:
            odd += 1
    assert odd > 0


def test_lending_attestation_modes():
    from embit import ec

    from lending_dlc_builder import build_collateral_dlc

    def xonly() -> str:
        return ec.PrivateKey(secrets.token_bytes(32)).get_public_key().xonly().hex()

    def compressed() -> str:
        return ec.PrivateKey(secrets.token_bytes(32)).get_public_key().serialize().hex()

    base = dict(
        adaptor_point_hex=compressed(),
        borrower_pubkey_hex=xonly(),
        repay_pubkey_hex=xonly(),
        lender_pubkey_hex=xonly(),
        oracle_pubkey_hex=xonly(),
        safety_timeout=900_000,
        protocol_version=2,
    )
    d_oracle = build_collateral_dlc(**base, attestation_mode="oracle")
    d_fal = build_collateral_dlc(
        **{k: v for k, v in base.items() if k != "oracle_pubkey_hex"},
        attestation_mode="fal",
        attestation_hash_hex=secrets.token_bytes(32).hex(),
    )
    d_ft = build_collateral_dlc(
        **{k: v for k, v in base.items() if k != "oracle_pubkey_hex"},
        attestation_mode="fixed_term",
        lender_claim_cltv_height=899_000,  # gap to safety_timeout 900_000 is 1000 >= 144
    )
    for d in (d_oracle, d_fal, d_ft):
        assert d.internal_private_key is None
        assert d.address.startswith("bc1p")
        assert len(d.repay_script) == 68  # 34-byte repay script hex


def test_lending_v1_removed():
    from embit import ec

    from lending_dlc_builder import build_collateral_dlc

    try:
        build_collateral_dlc(
            adaptor_point_hex=ec.PrivateKey(secrets.token_bytes(32))
            .get_public_key()
            .serialize()
            .hex(),
            borrower_pubkey_hex=ec.PrivateKey(secrets.token_bytes(32))
            .get_public_key()
            .xonly()
            .hex(),
            lender_pubkey_hex=ec.PrivateKey(secrets.token_bytes(32))
            .get_public_key()
            .xonly()
            .hex(),
            oracle_pubkey_hex=ec.PrivateKey(secrets.token_bytes(32))
            .get_public_key()
            .xonly()
            .hex(),
            safety_timeout=900_000,
            protocol_version=1,
        )
        raise AssertionError("v1 must be rejected")
    except ValueError:
        pass


def _load_signer(tag: str):
    if not SIGNER_PATH.is_file():
        raise FileNotFoundError(f"psbt-signer not found at {SIGNER_PATH}")
    spec = importlib.util.spec_from_file_location(tag, SIGNER_PATH)
    signer = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(signer)
    return signer


def test_signer_adaptor_matches_dlc_builder():
    signer = _load_signer("psbt_signer_adapt")

    from dlc_builder import adaptor_complete as lib_complete
    from dlc_builder import adaptor_presign as lib_presign
    from dlc_builder import point_from_secret as lib_point

    d = secrets.token_bytes(32)
    t = secrets.token_bytes(32)
    msg = secrets.token_bytes(32)
    T = lib_point(t)
    lib_ps = lib_presign(d, msg, T)
    sig_ps = signer.adaptor_presign(d, msg, T)
    assert lib_ps == sig_ps
    lib_sig = lib_complete(lib_ps, t)
    sig_sig = signer.adaptor_complete(sig_ps, t)
    assert lib_sig == sig_sig


def test_signer_analyze_claim_script():
    signer = _load_signer("psbt_signer_analyze")

    from lending_dlc_builder.lending_scripts import build_lending_v2_repay_script

    key = secrets.token_bytes(32)
    script = build_lending_v2_repay_script(key)
    info = signer.analyze_script(script)
    assert info["type"] == "v2_claim"
    assert info["receiver_pubkey"] == key


def test_signer_analyze_cltv_not_labeled_refund_only():
    signer = _load_signer("psbt_signer_cltv")
    from lending_dlc_builder.lending_scripts import build_lender_claim_timelocked_script

    key = secrets.token_bytes(32)
    script = build_lender_claim_timelocked_script(900_000, key)
    info = signer.analyze_script(script)
    assert info["type"] == "timelocked_single_key"
    assert "refund OR fixed-term" in info["description"] or "CLTV" in info["description"]


def test_signer_version_and_imports():
    signer = _load_signer("psbt_signer_api")
    assert signer.VERSION.startswith("2.")
    assert callable(signer.build_v2_claim_psbt)
    assert callable(signer.adaptor_extract)
    assert callable(signer.verify_leaf)


def test_loan_delivery_plus_collateral_example():
    import lending_dlc_builder.example_loan as ex

    ex.main()


def test_swap_example():
    import dlc_builder.example_swap as ex

    ex.main()


def main() -> int:
    print("taproot-dlc-lab tests\n")
    tests = [
        ("dlc_builder adaptor roundtrip", test_dlc_adaptor_roundtrip),
        ("dlc_builder multi-network build", test_dlc_build_multi_network),
        ("dlc_builder parity vs coincurve", test_dlc_parity_regression),
        ("lending_dlc_builder attestation modes", test_lending_attestation_modes),
        ("lending_dlc_builder v1 removed", test_lending_v1_removed),
        ("example_swap.py", test_swap_example),
        ("example_loan.py", test_loan_delivery_plus_collateral_example),
    ]
    if SIGNER_PATH.is_file():
        tests.extend(
            [
                ("psbt-signer adaptor == dlc_builder", test_signer_adaptor_matches_dlc_builder),
                ("psbt-signer analyze_script repay leaf", test_signer_analyze_claim_script),
                ("psbt-signer CLTV leaf labeling", test_signer_analyze_cltv_not_labeled_refund_only),
                ("psbt-signer import + APIs", test_signer_version_and_imports),
            ]
        )
    else:
        print(f"  SKIP  psbt-signer interop ({SIGNER_PATH} missing)\n")
    for name, fn in tests:
        run(name, fn)
    print(f"\n{PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
