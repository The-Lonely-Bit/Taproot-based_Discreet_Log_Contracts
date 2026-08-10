# Witness stacks — collateral DLC (Tapscript leaves)

This document describes **what must appear in the witness** to spend the **collateral** output along each **script path**. It matches `lending_scripts.py` in this package.

For **Taproot script-path** spends (BIP-341 / BIP-342), the full transaction witness typically includes, **in addition** to the items below, the **tapscript** and **control block** (see `LendingDLCDescriptor` fields: `repay_script`, `lender_claim_script`, `safety_script`, and corresponding `*_control_block`).

**Notation:** *Stack bottom → top* is the witness element order **before** script execution (last element is top-of-stack). Schnorr signatures are **64-byte** BIP-340.

**Trust note:** Collateral **repay** is **server-gated** (adaptor secret `t` released after observed loan repayment). That is protocol policy, not on-chain atomicity.

---

## 1. Repay leaf (default)

**Script shape:** `<repay_xonly> OP_CHECKSIG`

`repay_xonly` is `repay_pubkey` in the descriptor (may be an ephemeral browser key, not the borrower's wallet key).

| Stack (bottom → top) | Role |
|----------------------|------|
| `completed_schnorr_sig` | BIP-340 signature = `adaptorComplete(presig, t)` under the repay key |

**Off-chain (not in witness stack items above):**

1. Borrower (or server on borrower's behalf) holds a **claim pre-signature** `(R', s')` over the repay sighash.
2. Server releases adaptor secret `t` only after **confirmed on-chain loan repayment**.
3. Client completes: standard 64-byte Schnorr valid under `repay_xonly`.

Adaptor math: [`dlc_builder/adaptor_sig.py`](../dlc_builder/adaptor_sig.py) and [`../psbt-signer/signer.py`](../../psbt-signer/signer.py).

---

## 2. Lender-claim leaf — three variants (attestation mode)

Only **one** of these is compiled into a given output; chosen by `attestation_mode` in `build_collateral_dlc`.

### 2a. `oracle` mode

**Script shape:** `<oracle_xonly> OP_CHECKSIGVERIFY <lender_xonly> OP_CHECKSIG`

Script pushes the oracle key, then `CHECKSIGVERIFY` pops **top-of-stack** as the signature for that key. Therefore the oracle signature must be **on top**.

| Stack (bottom → top) | Role |
|----------------------|------|
| `lender_sig` | Lender signature (`CHECKSIG`) |
| `oracle_sig` | Oracle attestation signature (`CHECKSIGVERIFY`) |

Oracle attestation is any Schnorr signature by the oracle key over the claim sighash — **not** DLC-style outcome-bound messaging.

### 2b. `fixed_term` mode

**Script shape:** `<height> OP_CHECKLOCKTIMEVERIFY OP_DROP <lender_xonly> OP_CHECKSIG`

| Stack (bottom → top) | Role |
|----------------------|------|
| `lender_sig` | Single Schnorr signature |

**Transaction:** `nLockTime` **≥ `lender_claim_cltv_height`**.

`safety_timeout` must be strictly greater than `lender_claim_cltv_height + 144` (builder-enforced).

### 2c. `fal` mode (hashlock)

**Script shape:** `OP_SHA256 <h_32> OP_EQUALVERIFY <lender_xonly> OP_CHECKSIG`

| Stack (bottom → top) | Role |
|----------------------|------|
| `lender_sig` | Lender Schnorr signature |
| `preimage` | 32 bytes where `SHA256(preimage) == H` (committed in-script) |

---

## 3. Safety refund leaf

**Script shape:** `<timeout> OP_CHECKLOCKTIMEVERIFY OP_DROP <borrower_xonly> OP_CHECKSIG`

| Stack (bottom → top) | Role |
|----------------------|------|
| `borrower_sig` | Borrower **wallet** signature |

**Transaction:** `nLockTime` **≥ `safety_timeout`** (`safety_timeout` must be positive).

---

## Summary table

| Leaf | Modes | Witness stack (bottom → top) |
|------|--------|------------------------------|
| Repay | default | `completed_schnorr_sig` |
| Lender claim | `oracle` | `lender_sig`, `oracle_sig` |
| Lender claim | `fixed_term` | `lender_sig` (+ locktime ≥ CLTV height) |
| Lender claim | `fal` | `lender_sig`, `preimage` |
| Safety | all | `borrower_sig` (+ locktime ≥ safety timeout) |

---

## Loan delivery DLC (separate output)

The **loan delivery** leg is a **2-leaf DLC** built with `dlc_builder.build_dlc` (not this package). Claim witness:

| Stack (bottom → top) | Role |
|----------------------|------|
| `completed_schnorr_sig` | Adaptor-completed claim under borrower's ephemeral key |

---

## References

- [BIP-341 — Taproot](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP-342 — Tapscript](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
- [`dlc_builder/README.md`](../dlc_builder/README.md)
