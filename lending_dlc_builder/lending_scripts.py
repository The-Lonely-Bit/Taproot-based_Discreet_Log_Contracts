"""
Lending-specific Tapscript leaf builders for 3-leaf collateral DLCs.

Three leaves:
  1. Repay   – v2: single borrower key + off-chain BIP-340 adaptor (default)
  2. Lender Claim – oracle + lender / FAL hashlock / fixed-term CLTV
  3. Safety Refund – CLTV + borrower
"""
import logging
from typing import Any, Dict, Optional

from .script_builder import Script, read_script_pushdata

logger = logging.getLogger(__name__)


def parse_fal_hashlock_script(script: bytes) -> Optional[Dict[str, Any]]:
    """Parse FAL hashlock tapscript; accepts any valid push encoding."""
    if not script:
        return None
    i = 0
    if script[i] != Script.OP_SHA256:
        return None
    i += 1
    h_push = read_script_pushdata(script, i)
    if not h_push or len(h_push[0]) != 32:
        return None
    i = h_push[1]
    if i >= len(script) or script[i] != Script.OP_EQUALVERIFY:
        return None
    i += 1
    lender_push = read_script_pushdata(script, i)
    if not lender_push or len(lender_push[0]) != 32:
        return None
    i = lender_push[1]
    if i != len(script) - 1 or script[i] != Script.OP_CHECKSIG:
        return None
    return {"hash_commitment": h_push[0], "lender_pubkey": lender_push[0]}


def fal_hashlock_commitment_from_script(script: bytes) -> Optional[bytes]:
    """Parse 32-byte hash commitment H from FAL lender-claim hashlock tapscript."""
    parsed = parse_fal_hashlock_script(script)
    return parsed["hash_commitment"] if parsed else None


def build_lending_v2_repay_script(borrower_pubkey: bytes) -> bytes:
    """
    v2 collateral repay leaf — single borrower (or ephemeral repay) key.

    Script: <borrower_xonly> OP_CHECKSIG

    Atomicity for repay is server-gated (adaptor secret released only after
    confirmed repayment), but completion uses a real BIP-340 adaptor signature —
    not v1 2-of-2 co-sign.
    """
    if len(borrower_pubkey) != 32:
        raise ValueError(f"borrower_pubkey must be 32 bytes (x-only), got {len(borrower_pubkey)}")
    s = Script()
    s.push_data(borrower_pubkey)
    s.op(Script.OP_CHECKSIG)
    return s.to_bytes()


def build_lender_claim_hashlock_script(secret_hash: bytes, lender_pubkey: bytes) -> bytes:
    """
    Leaf 2 (FAL) — Lender claims with preimage matching SHA256(secret_hash target).

    Script: OP_SHA256 <32-byte h> OP_EQUALVERIFY <lender_xonly> OP_CHECKSIG

    Witness (bottom→top): <64-byte lender_sig> <32-byte preimage>
    """
    if len(secret_hash) != 32:
        raise ValueError(f"secret_hash must be 32 bytes, got {len(secret_hash)}")
    if len(lender_pubkey) != 32:
        raise ValueError(f"lender_pubkey must be 32 bytes (x-only), got {len(lender_pubkey)}")
    s = Script()
    s.op(Script.OP_SHA256)
    s.push_data(secret_hash)
    s.op(Script.OP_EQUALVERIFY)
    s.push_data(lender_pubkey)
    s.op(Script.OP_CHECKSIG)
    return s.to_bytes()


def build_lender_claim_timelocked_script(cltv_height: int, lender_pubkey: bytes) -> bytes:
    """
    Leaf 2 (fixed-term, no liquidation) — Lender claims after absolute CLTV height.

    Script: <height> OP_CHECKLOCKTIMEVERIFY OP_DROP <lender_xonly> OP_CHECKSIG
    """
    if cltv_height < 0:
        raise ValueError(f"cltv_height must be non-negative, got {cltv_height}")
    if len(lender_pubkey) != 32:
        raise ValueError(f"lender_pubkey must be 32 bytes (x-only), got {len(lender_pubkey)}")
    s = Script()
    s.push_int(cltv_height)
    s.op(Script.OP_CHECKLOCKTIMEVERIFY)
    s.op(Script.OP_DROP)
    s.push_data(lender_pubkey)
    s.op(Script.OP_CHECKSIG)
    return s.to_bytes()


def build_lender_claim_script(oracle_pubkey: bytes, lender_pubkey: bytes) -> bytes:
    """
    Leaf 2 — Lender claims collateral with oracle attestation.

    Script: <oracle_xonly> OP_CHECKSIGVERIFY <lender_xonly> OP_CHECKSIG

    Witness stack (bottom → top): <lender_sig> <oracle_sig>
    (CHECKSIGVERIFY consumes the top item first against the oracle key.)

    Oracle signature is any Schnorr sig by the oracle key over the claim
    sighash — outcome binding is **policy**, not encoded in the script.
    """
    if len(oracle_pubkey) != 32:
        raise ValueError(f"oracle_pubkey must be 32 bytes (x-only), got {len(oracle_pubkey)}")
    if len(lender_pubkey) != 32:
        raise ValueError(f"lender_pubkey must be 32 bytes (x-only), got {len(lender_pubkey)}")

    s = Script()
    s.push_data(oracle_pubkey)
    s.op(Script.OP_CHECKSIGVERIFY)
    s.push_data(lender_pubkey)
    s.op(Script.OP_CHECKSIG)
    return s.to_bytes()


def build_safety_refund_script(timeout_blocks: int, borrower_pubkey: bytes) -> bytes:
    """
    Leaf 3 — Borrower emergency exit after collateral lock expires.

    Script: <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <borrower_xonly> OP_CHECKSIG

    Witness: <borrower_sig>   (nLockTime >= timeout)

    Timeout = col_tip + loan_duration_blocks + lender_grace_blocks.
    This is the ON-CHAIN collateral lock: the borrower cannot touch the
    collateral until this block height is reached. Before it, only the
    repay leaf (server-gated) or lender claim leaf (oracle-gated) can spend.
    Guarantees borrower can always recover if server AND oracle both fail.
    """
    if len(borrower_pubkey) != 32:
        raise ValueError(f"borrower_pubkey must be 32 bytes (x-only), got {len(borrower_pubkey)}")
    if timeout_blocks < 0:
        raise ValueError(f"timeout_blocks must be non-negative, got {timeout_blocks}")

    s = Script()
    s.push_int(timeout_blocks)
    s.op(Script.OP_CHECKLOCKTIMEVERIFY)
    s.op(Script.OP_DROP)
    s.push_data(borrower_pubkey)
    s.op(Script.OP_CHECKSIG)
    return s.to_bytes()
