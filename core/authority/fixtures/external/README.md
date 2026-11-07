# External fixtures

Test data copied from other portfolio repositories. **These files carry no authority here.** They exist so tests can check whether Cathedral's verification code can reproduce hashes that other repos have already sealed.

| File | Source | How it was produced |
|---|---|---|
| `zorel_authorship_receipt_body.json` | `ryansctt1994-sudo/zorel-kernel` @ `3da1802da9a3e92e023a309bd5ef101dd2d27001` | `build_receipt()` from `AUTHORSHIP_RECEIPT_E3_SEALED.py`, with `certificate_hash` set to `null` (the body the sealed hash is computed over) |

Sealed hash for that body: `33f78bde8ba348bd24d291e8b871684e85f83a2687dae393a3a86079acdfe9f5`.

If the source repo changes its receipt, this copy goes stale on purpose. Refresh it deliberately, and don't edit it by hand.
