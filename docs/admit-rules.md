# certpin admit rules

Signing input (ASCII, no spaces beyond those inside field values that docs forbid):

`v1|{kid}|{host}|{pins_csv}|{backup_csv}`

HMAC-SHA256 over that line, then base64url without `=` padding.

## Interacting gates

- leaf SPKI sha256 必须命中 pins 或 backup_pins
- 仅 backup 命中时报告 backup_used，但仍 allow
- alg 只能 sha256；host 必须 exact
- kid 撤销；空 pins 是 load failure

## Exit codes

- allow = 0
- deny = 1
- load failure = 2

Deny must not write the store. Load failure must not write the store.

## Reason codes

Stable snake_case identifiers, one per failing gate:

- `kid_unknown` / `kid_revoked`: key id missing from the key ring, or not
  active (a revoked kid denies even when the HMAC itself verifies)
- `bad_signature`: recomputed HMAC over the signing line does not match `sig`
- `host_mismatch`: host is not an exact match
- `unsupported_alg`: alg other than sha256
- `pin_mismatch`: leaf SPKI sha256 hits neither pins nor backup_pins
- `backup_pin_mismatch`: backup pin list inconsistent with the signed
  commitment (a leaf-only check that ignores backup_pins misses this)
- `empty_pins`: pins list is empty (load failure, exit 2)
- `malformed_input`: input cannot be shaped into an admittable manifest
  (load failure, exit 2)

When only backup_pins hits, the decision is still allow and the report
notes carry `backup_used`.

## Fixture expectations

Allow cases: ok-primary, ok-backup

Deny cases: bad-sig, miss-pin, wrong-host, alg, revoked, empty, malformed, leaf-only-ignore-backup-fail

Reason codes should be stable snake_case identifiers matching the failing gate.
