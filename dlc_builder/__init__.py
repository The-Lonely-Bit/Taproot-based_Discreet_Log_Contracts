"""
Taproot DLC builder: shared script/Taproot helpers, output builder, and
BIP-340 adaptor signature math.
"""
from .adaptor_sig import (
    adaptor_complete,
    adaptor_extract,
    adaptor_presign,
    adaptor_verify,
    point_from_secret,
    pubkey_xonly,
    schnorr_verify,
)
from .builder import (
    DLCDescriptor,
    build_dlc,
    derive_unspendable_internal_key,
    derive_unspendable_internal_key_multi,
    generate_adaptor_secret,
)
from .script import Script, build_dlc_claim_script, build_dlc_refund_script, tagged_hash
from .taproot import (
    DEFAULT_HRP_MAP,
    TAPROOT_LEAF_VERSION,
    compute_merkle_proof,
    create_control_block,
    taproot_address_from_pubkey,
    taproot_leaf_hash,
    taproot_output_script,
    taproot_tree_helper,
    taproot_tweak_pubkey,
)

__all__ = [
    "DLCDescriptor",
    "Script",
    "build_dlc",
    "build_dlc_claim_script",
    "build_dlc_refund_script",
    "tagged_hash",
    "derive_unspendable_internal_key",
    "derive_unspendable_internal_key_multi",
    "generate_adaptor_secret",
    "adaptor_presign",
    "adaptor_verify",
    "adaptor_complete",
    "adaptor_extract",
    "pubkey_xonly",
    "point_from_secret",
    "schnorr_verify",
    "TAPROOT_LEAF_VERSION",
    "taproot_address_from_pubkey",
    "taproot_output_script",
    "taproot_leaf_hash",
    "taproot_tree_helper",
    "taproot_tweak_pubkey",
    "create_control_block",
    "compute_merkle_proof",
    "DEFAULT_HRP_MAP",
]
