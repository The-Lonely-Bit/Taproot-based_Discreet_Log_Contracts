# Collateral Taproot builder (`lending_dlc_builder`)

Builds a three-leaf Taproot collateral output (repay / lender-claim / safety refund). Loan-delivery outputs, when needed, are built with `dlc_builder`.

**Trust model:** repay is **server-gated** (adaptor secret release after observed repayment). This is not the same trust model as a pure swap claim/extract loop. Oracle / FAL / fixed-term lender-claim paths are policy-gated, not DLC-outcome-bound.

## Leaves

| Leaf | Role |
|------|------|
| Repay | Borrower reclaim after server releases adaptor completion material |
| Lender claim | Oracle, hashlock (FAL), or fixed-term CLTV — see `attestation_mode` |
| Safety | Time-locked borrower refund |

## Install

```bash
pip install -r ../requirements.txt
export PYTHONPATH=..
```

## Example

```python
from lending_dlc_builder import build_collateral_dlc

desc = build_collateral_dlc(
    adaptor_point_hex="03" + "11" * 32,  # must be a real on-curve compressed point
    borrower_pubkey_hex="...",
    repay_pubkey_hex="...",
    lender_pubkey_hex="...",
    oracle_pubkey_hex="...",
    safety_timeout=900_000,
    network="mainnet",
    attestation_mode="oracle",
)
print(desc.address, desc.repay_script)
```

See `example_loan.py`, `test_v2_collateral.py`, and `WITNESS.md`.

## Attestation modes

| Mode | Lender-claim leaf |
|------|-------------------|
| `oracle` | Oracle `CHECKSIGVERIFY` + lender |
| `fal` | SHA256 preimage check + lender |
| `fixed_term` | CLTV + lender (`safety_timeout` must clear lender CLTV by ≥144 blocks) |
