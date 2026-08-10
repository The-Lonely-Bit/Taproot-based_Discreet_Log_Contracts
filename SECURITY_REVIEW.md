# Security review — GreyBound

**Reviewer:** [GreyBound](https://greybound.com)  
**Date:** 2026-08-10  
**Tag:** `greybound-review-2026-08-10`

Independent security review and hardening of the Taproot DLC builders and offline Signer by GreyBound.

## Scope

- `dlc_builder/` — swap construction, Taproot helpers, adaptor signatures
- `lending_dlc_builder/` — collateral construction
- `Signer/` — offline PSBT inspection and signing

## Outcome

GreyBound reviewed the implementation, applied hardening fixes, consolidated packaging onto a single `dlc_builder`, and added regression tests for Taproot control-block handling, builder validation, and Signer behavior.

## Notes

Reference / research libraries for study and integration testing. Operators should still run their own spendability checks before mainnet use.

## Checks

```bash
pip install -r requirements.txt
export PYTHONPATH=.
python3 dlc_builder/test_roundtrip.py
python3 lending_dlc_builder/test_v2_collateral.py
python3 test_parity_hardening.py
python3 test_opensource_stack.py
```
