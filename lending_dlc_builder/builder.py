"""
Lending DLC Builder — 3-leaf collateral DLC for cross-chain lending.

Builds a Tapscript MAST tree with:
  Leaf 0: Repay          (single-key + off-chain adaptor completion)
  Leaf 1: Lender Claim   (oracle + lender / FAL / fixed_term)
  Leaf 2: Safety Refund  (CLTV + borrower)

Internal key is always NUMS-based (unspendable). The old public-data-derived
internal private key path has been removed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from dlc_builder import derive_unspendable_internal_key_multi
from dlc_builder.adaptor_sig import is_valid_xonly_pubkey
from dlc_builder.taproot import (
    TAPROOT_LEAF_VERSION,
    compute_merkle_proof,
    create_control_block,
    taproot_address_from_pubkey,
    taproot_leaf_hash,
    taproot_output_script,
    taproot_tree_helper,
    taproot_tweak_pubkey,
)

from . import attestation as att_modes
from .lending_scripts import (
    build_lender_claim_hashlock_script,
    build_lender_claim_script,
    build_lender_claim_timelocked_script,
    build_lending_v2_repay_script,
    build_safety_refund_script,
)

# Minimum gap (blocks) between lender fixed-term unlock and borrower safety refund.
_MIN_SAFETY_GAP_BLOCKS = 144


@dataclass
class LendingDLCDescriptor:
    """Complete descriptor for a 3-leaf collateral DLC."""

    borrower_pubkey: str
    lender_pubkey: str
    oracle_pubkey: str
    adaptor_point: str
    safety_timeout: int

    internal_pubkey: str
    internal_private_key: Optional[str]
    merkle_root: str
    output_pubkey: str
    output_key_parity: int

    repay_script: str
    lender_claim_script: str
    safety_script: str

    repay_leaf_hash: str
    lender_claim_leaf_hash: str
    safety_leaf_hash: str

    repay_control_block: str
    lender_claim_control_block: str
    safety_control_block: str

    address: str
    scriptpubkey: str

    repay_pubkey: str = ""
    attestation_mode: str = "oracle"
    attestation_hash_hex: str = ""
    lender_claim_cltv_height: int = 0


def _normalize_xonly(pubkey_hex: str, name: str) -> str:
    pubkey_hex = pubkey_hex.strip().lower()
    if len(pubkey_hex) == 64:
        raw = bytes.fromhex(pubkey_hex)
    elif len(pubkey_hex) == 66 and pubkey_hex[:2] in ("02", "03"):
        raw = bytes.fromhex(pubkey_hex[2:])
    else:
        raise ValueError(f"{name} invalid length {len(pubkey_hex)}")
    if not is_valid_xonly_pubkey(raw):
        raise ValueError(f"{name} is not a valid secp256k1 x-only pubkey")
    return raw.hex()


def build_collateral_dlc(
    adaptor_point_hex: str,
    borrower_pubkey_hex: str,
    lender_pubkey_hex: str,
    oracle_pubkey_hex: str = "",
    safety_timeout: int = 0,
    network: str = "mainnet",
    attestation_mode: str = "oracle",
    attestation_hash_hex: str = "",
    lender_claim_cltv_height: int = 0,
    *,
    protocol_version: int = 2,
    repay_pubkey_hex: str = "",
) -> LendingDLCDescriptor:
    """
    Build a 3-leaf collateral DLC for cross-chain lending.

    Only the NUMS / single-key-repay construction is supported.
    ``protocol_version`` must be 2 (kept for API compatibility).
    """
    if protocol_version != 2:
        raise ValueError(
            "protocol_version=1 is no longer supported. Use protocol_version=2."
        )
    if len(adaptor_point_hex) != 66 or adaptor_point_hex[:2] not in ("02", "03"):
        raise ValueError(
            f"adaptor_point must be 66 hex compressed pubkey, got {len(adaptor_point_hex)}"
        )
    if safety_timeout <= 0:
        raise ValueError(f"safety_timeout must be positive, got {safety_timeout}")
    if attestation_mode not in att_modes.VALID_MODES:
        raise ValueError(f"invalid attestation_mode: {attestation_mode}")

    borrower_hex = _normalize_xonly(borrower_pubkey_hex, "borrower_pubkey")
    repay_hex = _normalize_xonly(repay_pubkey_hex or borrower_pubkey_hex, "repay_pubkey")
    lender_hex = _normalize_xonly(lender_pubkey_hex, "lender_pubkey")

    adaptor_point = bytes.fromhex(adaptor_point_hex)
    # Validate adaptor point is on-curve (compressed).
    from embit.ec import PublicKey

    PublicKey.parse(adaptor_point)

    borrower = bytes.fromhex(borrower_hex)
    lender = bytes.fromhex(lender_hex)

    if attestation_mode == att_modes.ORACLE:
        if not oracle_pubkey_hex:
            raise ValueError("oracle mode requires oracle_pubkey_hex")
        oracle_hex = _normalize_xonly(oracle_pubkey_hex, "oracle_pubkey")
        oracle = bytes.fromhex(oracle_hex)
        lender_claim = build_lender_claim_script(oracle, lender)
    elif attestation_mode == att_modes.FAL:
        if len(attestation_hash_hex) != 64:
            raise ValueError("FAL mode requires attestation_hash_hex (64 hex chars)")
        oracle_hex = ""
        lender_claim = build_lender_claim_hashlock_script(
            bytes.fromhex(attestation_hash_hex), lender
        )
    elif attestation_mode == att_modes.FIXED_TERM:
        if lender_claim_cltv_height <= 0:
            raise ValueError("fixed_term mode requires positive lender_claim_cltv_height")
        if safety_timeout <= lender_claim_cltv_height + _MIN_SAFETY_GAP_BLOCKS:
            raise ValueError(
                f"safety_timeout ({safety_timeout}) must be > "
                f"lender_claim_cltv_height + {_MIN_SAFETY_GAP_BLOCKS} "
                f"(got lender_claim_cltv_height={lender_claim_cltv_height})"
            )
        oracle_hex = ""
        lender_claim = build_lender_claim_timelocked_script(
            lender_claim_cltv_height, lender
        )
    else:
        raise ValueError(f"unsupported attestation_mode: {attestation_mode}")

    repay = build_lending_v2_repay_script(bytes.fromhex(repay_hex))
    safety = build_safety_refund_script(safety_timeout, borrower)

    scripts = [repay, lender_claim, safety]
    merkle_root, leaf_hashes = taproot_tree_helper(scripts)
    repay_lh, claim_lh, safety_lh = leaf_hashes

    for i, (sc, lh) in enumerate(zip(scripts, leaf_hashes)):
        expected = taproot_leaf_hash(sc, TAPROOT_LEAF_VERSION)
        if lh != expected:
            raise ValueError(f"Leaf {i} hash mismatch")

    int_pub = derive_unspendable_internal_key_multi(repay_lh, claim_lh, safety_lh)
    output_pubkey, parity = taproot_tweak_pubkey(int_pub, merkle_root)
    spk = taproot_output_script(output_pubkey)
    address = taproot_address_from_pubkey(output_pubkey, network)

    repay_proof = compute_merkle_proof(repay_lh, leaf_hashes)
    claim_proof = compute_merkle_proof(claim_lh, leaf_hashes)
    safety_proof = compute_merkle_proof(safety_lh, leaf_hashes)

    repay_cb = create_control_block(
        int_pub,
        repay,
        repay_proof,
        leaf_version=TAPROOT_LEAF_VERSION,
        output_key_parity=parity,
    )
    claim_cb = create_control_block(
        int_pub,
        lender_claim,
        claim_proof,
        leaf_version=TAPROOT_LEAF_VERSION,
        output_key_parity=parity,
    )
    safety_cb = create_control_block(
        int_pub,
        safety,
        safety_proof,
        leaf_version=TAPROOT_LEAF_VERSION,
        output_key_parity=parity,
    )

    for name, cb in [("repay", repay_cb), ("claim", claim_cb), ("safety", safety_cb)]:
        if cb[0] not in (0xC0, 0xC1):
            raise ValueError(f"Invalid {name} control block header: 0x{cb[0]:02x}")
        if (cb[0] & 1) != (parity & 1):
            raise RuntimeError(f"{name} control-block parity mismatch")

    return LendingDLCDescriptor(
        borrower_pubkey=borrower_hex,
        repay_pubkey=repay_hex,
        lender_pubkey=lender_hex,
        oracle_pubkey=oracle_hex,
        adaptor_point=adaptor_point_hex,
        safety_timeout=safety_timeout,
        attestation_mode=attestation_mode,
        attestation_hash_hex=attestation_hash_hex if attestation_mode == att_modes.FAL else "",
        lender_claim_cltv_height=(
            lender_claim_cltv_height if attestation_mode == att_modes.FIXED_TERM else 0
        ),
        internal_pubkey=int_pub.hex(),
        internal_private_key=None,
        merkle_root=merkle_root.hex(),
        output_pubkey=output_pubkey.hex(),
        output_key_parity=parity,
        repay_script=repay.hex(),
        lender_claim_script=lender_claim.hex(),
        safety_script=safety.hex(),
        repay_leaf_hash=repay_lh.hex(),
        lender_claim_leaf_hash=claim_lh.hex(),
        safety_leaf_hash=safety_lh.hex(),
        repay_control_block=repay_cb.hex(),
        lender_claim_control_block=claim_cb.hex(),
        safety_control_block=safety_cb.hex(),
        address=address,
        scriptpubkey=spk.hex(),
    )
