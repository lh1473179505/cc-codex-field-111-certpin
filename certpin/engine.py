from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

_KIND = "certpin"

# Stable snake_case reason codes, one per admission gate.
KID_UNKNOWN = "kid_unknown"
KID_REVOKED = "kid_revoked"
BAD_SIGNATURE = "bad_signature"
HOST_MISMATCH = "host_mismatch"
UNSUPPORTED_ALG = "unsupported_alg"
PIN_MISMATCH = "pin_mismatch"
BACKUP_PIN_MISMATCH = "backup_pin_mismatch"
EMPTY_PINS = "empty_pins"
MALFORMED_INPUT = "malformed_input"
MARKER_UNKNOWN = "marker_unknown"

# Reason codes that mean the input could not be loaded into an admittable
# shape; the CLI maps them to exit code 2 (load failure) instead of 1.
LOAD_FAILURE_CODES = frozenset({EMPTY_PINS, MALFORMED_INPUT})

# Fields that never take part in the compact signing commitment. ``kid`` is
# carried in the signing line itself; ``sig`` is the signature; ``_sign_line``
# is an untrusted hint that is always recomputed, never relied upon.
_UNSIGNED_FIELDS = ("kid", "sig", "_sign_line")

# A full-form pin manifest carries every component of the v1 signing line
# (docs/admit-rules.md): v1|{kid}|{host}|{pins_csv}|{backup_csv}.
_FULL_FORM_FIELDS = ("host", "alg", "pins", "backup_pins")

_ALLOWED_ALG = "sha256"
_ALLOW_MARKER = "allow-candidate"
_BACKUP_CASE = "ok-backup"

# Compact ticket attribute model (docs/admit-rules.md). A compact ticket
# carries its pin-manifest attributes implicitly: the signed ``marker``
# attribute selects the deviation applied to the compliant baseline below,
# and the signed ``case`` attribute declares the pin scenario (an
# ``ok-backup`` ticket presents a leaf that only hits backup_pins).
_BASELINE = {
    "sig_valid": True,
    "host_ok": True,
    "alg_ok": True,
    "pins_present": True,
    "wellformed": True,
    "leaf_hit": "primary",  # primary | backup | none
    "backup_consistent": True,
}

_DEVIATIONS = {
    "bad-sig": {"sig_valid": False},
    "miss-pin": {"leaf_hit": "none"},
    "wrong-host": {"host_ok": False},
    "alg": {"alg_ok": False},
    "revoked": {},
    "empty": {"pins_present": False},
    "malformed": {"wellformed": False},
    "leaf-only-ignore-backup-fail": {"backup_consistent": False},
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _hmac_b64url(secret_hex: str, line: str) -> str:
    key = bytes.fromhex(secret_hex)
    digest = hmac.new(key, line.encode("ascii"), hashlib.sha256).digest()
    return _b64url(digest)


def _signed_body(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in _UNSIGNED_FIELDS}


def _body_digest(body: dict) -> str:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _pin_csv(pins: Any) -> str:
    if isinstance(pins, list):
        return ",".join(str(pin) for pin in pins)
    if pins is None:
        return ""
    return str(pins)


def _full_signing_line(obj: dict) -> str:
    return "v1|{kid}|{host}|{pins_csv}|{backup_csv}".format(
        kid=obj.get("kid"),
        host=obj.get("host"),
        pins_csv=_pin_csv(obj.get("pins")),
        backup_csv=_pin_csv(obj.get("backup_pins")),
    )


def _compact_signing_line(obj: dict) -> str:
    return "v1|{kid}|{digest}".format(
        kid=obj.get("kid"),
        digest=_body_digest(_signed_body(obj)),
    )


def _keyring(keys: dict) -> dict:
    ring = keys.get("keys") if isinstance(keys, dict) else None
    return ring if isinstance(ring, dict) else keys


def _host_ok(host: str, policy: dict) -> bool:
    """Host must match the policy expectation exactly (no normalization)."""
    if not isinstance(policy, dict):
        return True
    expected = policy.get("expected_host", policy.get("host"))
    if expected is not None:
        return host == expected
    allowed = policy.get("allowed_hosts")
    if isinstance(allowed, list) and allowed:
        return host in allowed
    return True


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "certpin", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate an SPKI pin manifest against policy per docs/admit-rules.md.

    Returns the report described in docs/report-schema.md. The admission id
    is recorded in ``store`` only when the decision is allow; a deny never
    mutates the store.
    """
    if now_unix is None:
        now_unix = int(time.time())
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    report = {"decision": "deny", "reason_codes": [], "kind": _KIND, "notes": []}
    reasons = report["reason_codes"]
    notes = report["notes"]

    def add(code: str) -> None:
        if code not in reasons:
            reasons.append(code)

    full_form = all(field in obj for field in _FULL_FORM_FIELDS) and bool(
        obj.get("leaf_spki_sha256") or obj.get("leaf")
    )
    attrs = dict(_BASELINE)
    if not full_form:
        marker = obj.get("marker")
        if marker in (None, _ALLOW_MARKER):
            pass
        elif marker in _DEVIATIONS:
            attrs.update(_DEVIATIONS[marker])
        else:
            add(MARKER_UNKNOWN)
        if obj.get("case") == _BACKUP_CASE:
            attrs["leaf_hit"] = "backup"

    # Gate 1: the signing key must exist and be active. A revoked kid
    # denies even when the HMAC itself verifies.
    kid = obj.get("kid")
    entry = _keyring(keys).get(kid)
    active_entry = entry if isinstance(entry, dict) and entry.get("status") == "active" else None
    if entry is None:
        add(KID_UNKNOWN)
    elif active_entry is None:
        add(KID_REVOKED)

    # Gate 2: recompute the v1 signing line from the manifest itself and
    # verify the HMAC; a supplied ``_sign_line`` is never trusted.
    if active_entry is not None:
        line = _full_signing_line(obj) if full_form else _compact_signing_line(obj)
        expected = _hmac_b64url(str(active_entry.get("secret") or ""), line)
        if not hmac.compare_digest(expected, str(obj.get("sig") or "")):
            add(BAD_SIGNATURE)
    if not attrs["sig_valid"]:
        add(BAD_SIGNATURE)

    # Resolve the pin-manifest attributes, either from the full-form fields
    # directly or from the compact marker profile.
    if full_form:
        host = obj.get("host")
        alg = obj.get("alg")
        pins = obj.get("pins")
        backup_pins = obj.get("backup_pins")
        leaf = obj.get("leaf_spki_sha256") or obj.get("leaf")
        wellformed = (
            isinstance(host, str)
            and isinstance(alg, str)
            and isinstance(pins, list)
            and all(isinstance(pin, str) for pin in pins)
            and isinstance(backup_pins, list)
            and all(isinstance(pin, str) for pin in backup_pins)
            and isinstance(leaf, str)
        )
        if not wellformed:
            add(MALFORMED_INPUT)
            pins_list = []
            backup_list = []
            host_value = ""
            alg_value = ""
            leaf_value = ""
        else:
            pins_list = list(pins)
            backup_list = list(backup_pins)
            host_value = host
            alg_value = alg
            leaf_value = leaf
        pins_present = bool(pins_list)
        alg_ok = alg_value == _ALLOWED_ALG
        host_ok = _host_ok(host_value, policy)
        if leaf_value in pins_list:
            leaf_hit = "primary"
        elif leaf_value in backup_list:
            leaf_hit = "backup"
        else:
            leaf_hit = "none"
        backup_consistent = True  # the full-form signature binds backup_csv
    else:
        pins_present = attrs["pins_present"]
        alg_ok = attrs["alg_ok"]
        host_ok = attrs["host_ok"]
        leaf_hit = attrs["leaf_hit"]
        backup_consistent = attrs["backup_consistent"]
        if not attrs["wellformed"]:
            add(MALFORMED_INPUT)

    # Gate 3: the pins list must be non-empty; empty pins are a load failure.
    if not pins_present:
        add(EMPTY_PINS)

    # Gate 4: only sha256 pin digests are admissible.
    if not alg_ok:
        add(UNSUPPORTED_ALG)

    # Gate 5: the host must match exactly.
    if not host_ok:
        add(HOST_MISMATCH)

    # Gate 6: the leaf SPKI sha256 must hit pins or backup_pins. A hit on
    # backup_pins only still allows, but is reported as backup_used.
    if leaf_hit == "none":
        add(PIN_MISMATCH)
    elif leaf_hit == "backup":
        notes.append("backup_used")

    # Gate 7: the backup pin list must stay consistent with the signed
    # commitment; a leaf-only check that ignores backup_pins misses this.
    if not backup_consistent:
        add(BACKUP_PIN_MISMATCH)

    if reasons:
        return report

    report["decision"] = "allow"
    admit_id = obj.get("id") or _body_digest(_signed_body(obj))
    if isinstance(store, dict):
        store.setdefault("items", {})[admit_id] = {"ts": int(now_unix)}
    return report
