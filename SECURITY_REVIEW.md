# GreyBound review

**Status:** Reviewed & hardened by [GreyBound](https://greybound.com) (internal engineering review)  
**Date:** 2026-08-10  
**Tag:** `greybound-review-2026-08-10`

Internal review of the Taproot DLC builders and offline Signer. Not a formal third-party audit certification.

## Scope

- `dlc_builder/` — swap construction, Taproot helpers, adaptor signatures
- `lending_dlc_builder/` — collateral construction
- `Signer/` — offline PSBT inspection and signing

## Outcome

Hardening and correctness fixes were applied for Taproot control-block handling, collateral builder validation, witness documentation, and Signer review-before-sign behavior. Package layout consolidated to a single `dlc_builder` (no separate `dlc_v2_builder`).

## Limits

Research / reference code. Do not treat as production-certified. Lending repay paths remain server-gated by design.

## Checks

```bash
pip install -r requirements.txt
export PYTHONPATH=.
python3 dlc_builder/test_roundtrip.py
python3 lending_dlc_builder/test_v2_collateral.py
python3 test_parity_hardening.py
python3 test_opensource_stack.py
```
