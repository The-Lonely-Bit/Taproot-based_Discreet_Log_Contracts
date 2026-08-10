"""
Bitcoin script utilities for DLC construction.

Claim path: single-key CHECKSIG (adaptor atomicity is off-chain).
Refund path: CLTV + sender CHECKSIG.
"""
import hashlib
from typing import Union


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP-340 tagged hash: TaggedHash(tag, x) = SHA256(SHA256(tag) || SHA256(tag) || x)."""
    tag_hash = sha256(tag.encode("utf-8"))
    return sha256(tag_hash + tag_hash + data)


class Script:
    """Minimal Bitcoin script builder for DLC scripts."""
    OP_0 = 0x00
    OP_1NEGATE = 0x4f
    OP_1 = 0x51
    OP_DROP = 0x75
    OP_CHECKSIG = 0xac
    OP_CHECKSIGVERIFY = 0xad
    OP_CHECKLOCKTIMEVERIFY = 0xb1

    def __init__(self):
        self.script = bytearray()

    def push_data(self, data: Union[bytes, bytearray]) -> "Script":
        n = len(data)
        if n <= 75:
            self.script.append(n)
            self.script.extend(data)
        elif n <= 0xFF:
            self.script.append(0x4C)
            self.script.append(n)
            self.script.extend(data)
        else:
            self.script.append(0x4D)
            self.script.extend(n.to_bytes(2, "little"))
            self.script.extend(data)
        return self

    def push_int(self, n: int) -> "Script":
        if n == -1:
            self.script.append(self.OP_1NEGATE)
        elif n == 0:
            self.script.append(self.OP_0)
        elif 1 <= n <= 16:
            self.script.append(self.OP_1 + n - 1)
        else:
            self.push_data(self._encode_scriptnum(n))
        return self

    def _encode_scriptnum(self, n: int) -> bytes:
        if n == 0:
            return b""
        neg = n < 0
        n = abs(n)
        out = []
        while n:
            out.append(n & 0xFF)
            n >>= 8
        if out[-1] & 0x80:
            out.append(0x80 if neg else 0x00)
        elif neg:
            out[-1] |= 0x80
        return bytes(out)

    def op(self, opcode: int) -> "Script":
        self.script.append(opcode)
        return self

    def to_bytes(self) -> bytes:
        return bytes(self.script)


def build_dlc_claim_script(receiver_pubkey: bytes) -> bytes:
    """
    Claim path: <receiver_xonly> OP_CHECKSIG.

    Atomicity is off-chain via BIP-340 adaptor signatures (see adaptor_sig.py).
    """
    if len(receiver_pubkey) != 32:
        raise ValueError(f"Receiver pubkey must be 32 bytes (x-only), got {len(receiver_pubkey)}")
    script = Script()
    script.push_data(receiver_pubkey)
    script.op(Script.OP_CHECKSIG)
    return script.to_bytes()


def build_dlc_refund_script(timeout_blocks: int, sender_pubkey: bytes) -> bytes:
    """
    Refund path: <timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <sender_xonly> OP_CHECKSIG.
    Witness: <sender_sig>; nLockTime >= timeout_blocks.
    """
    if len(sender_pubkey) != 32:
        raise ValueError("Sender pubkey must be 32 bytes (x-only)")
    if timeout_blocks < 0:
        raise ValueError("Timeout must be non-negative")
    s = Script()
    s.push_int(timeout_blocks)
    s.op(Script.OP_CHECKLOCKTIMEVERIFY)
    s.op(Script.OP_DROP)
    s.push_data(sender_pubkey)
    s.op(Script.OP_CHECKSIG)
    return s.to_bytes()
