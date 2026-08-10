"""
Collateral DLC builder for cross-chain lending (3-leaf Taproot MAST).

NUMS internal key + single-key repay leaf. Loan delivery: ``dlc_builder.build_dlc``.

Repay is server-gated off-chain (adaptor secret release) — not cryptographically
atomic the way a pure swap claim/extract loop is.
"""
from . import attestation
from .builder import LendingDLCDescriptor, build_collateral_dlc
from .lending_scripts import build_lending_v2_repay_script

__all__ = [
    "LendingDLCDescriptor",
    "build_collateral_dlc",
    "build_lending_v2_repay_script",
    "attestation",
]
