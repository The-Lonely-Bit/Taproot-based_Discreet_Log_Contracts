# Taproot DLC builder (`dlc_builder`)

Builds Taproot swap outputs with a claim path and a time-locked refund path, and implements BIP-340 adaptor signature presign / verify / complete / extract. Also exports shared Taproot / script helpers used by `lending_dlc_builder`.

Install `coincurve` for Taproot key tweaking (preferred). Pure-Python fallback is available via adaptor math.

## Behavior

- Claim tapscript: `<receiver_xonly> CHECKSIG`
- Refund tapscript: CLTV + sender key
- Internal key: NUMS point (script-path spends)
- Adaptor point `T` is 33-byte compressed and stays off-chain

## Install

```bash
pip install -r requirements.txt   # embit + coincurve
export PYTHONPATH=..              # repo root: taproot-dlc-lab
```

## Build an output descriptor

```python
from dlc_builder import build_dlc, generate_adaptor_secret

secret_hex, point_hex = generate_adaptor_secret()

desc = build_dlc(
    receiver_pubkey_hex="...",  # 64-char x-only claim key
    sender_pubkey_hex="...",    # 64-char x-only refund key
    adaptor_point_hex=point_hex,
    timeout=850000,
    network="mainnet",          # or hrp= for other chains
)
print(desc.address, desc.claim_control_block)
```

## Adaptor API

```python
from dlc_builder import (
    adaptor_presign, adaptor_verify, adaptor_complete, adaptor_extract,
    pubkey_xonly, point_from_secret,
)
```

See `test_roundtrip.py` and `example_swap.py`.
