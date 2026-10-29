"""Read-only inspection of the Android backup format found in base.apk.

No tokens are generated, no counters are advanced, and no secrets are exported.
The optional binding check tests one supplied app-specific Android ID against
an existing metadata HMAC. It does not search for IDs or PINs.
"""

import argparse
import base64
import binascii
import getpass
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys


# Identified in setStatusBarBackgroundColor's property-name switch.
FIELD_ROLES = {
    "GQ": "token-label IV",
    "Y1": "encrypted token label",
    "Y2": "token-label HMAC",
    "ML": "token-label encryption salt (text)",
    "G7": "token-label authentication salt (text)",
    "11": "encrypted metadata",
    "R2": "metadata HMAC",
    "FR": "metadata encryption salt (text)",
    "MP": "metadata authentication salt (text)",
    "69": "metadata IV",
    "BV": "secret IV",
    "F3": "encrypted secret envelope",
    "53": "wrapping-key IV",
    "BA": "encrypted wrapping key",
    "B1": "wrapping-key HMAC",
    "TS": "wrapping-key encryption salt (text)",
    "W5": "wrapping-key authentication salt (text)",
    "Z55": "device-binding mode (text)",
}


def read_properties(path):
    """Read the ASCII, Base64-valued Properties format emitted by this app."""
    properties = {}
    pending = ""
    text = path.read() if hasattr(path, "read") else Path(path).read_text(encoding="ascii")
    for raw in text.splitlines():
        line = pending + raw.lstrip()
        trailing = len(line) - len(line.rstrip("\\"))
        if trailing % 2:
            pending = line[:-1]
            continue
        pending = ""
        if not line or line.startswith(("#", "!")):
            continue
        match = re.fullmatch(r"([A-Za-z0-9]+)\s*[=:]\s*(.*)", line)
        if not match:
            raise ValueError("Unsupported property syntax; expected app-generated Base64 properties.")
        name, value = match.groups()
        if name in properties:
            raise ValueError(f"Duplicate property: {name}")
        # Properties.store escapes '=' and may escape ':' in Base64 values.
        if re.search(r"\\[^=:\\]", value):
            raise ValueError(f"Unsupported escape in property {name}.")
        value = re.sub(r"\\([=:\\])", r"\1", value)
        try:
            properties[name] = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError(f"Invalid Base64 in property {name}.") from error
    if pending:
        raise ValueError("Unterminated property continuation.")
    return properties


def inspect_backup(properties):
    mode = properties.get("Z55", b"").decode("ascii")
    return {
        "binding_mode": mode or "not recorded",
        "binding_source": "Settings.Secure (app context)" if mode == "2" else "not established",
        "fields": {
            name: {"bytes": len(value), "role": FIELD_ROLES.get(name, "not mapped")}
            for name, value in sorted(properties.items())
        },
    }


def verify_android_id(properties, android_id):
    """Check one binding value using the app's direct R2/11 metadata HMAC.

    Static analysis: SHA256(UTF8(Base64Decode(MP) + binding + "/hou5Pa9htsf"))
    supplies the HMAC-SHA256 key; the message is Base64Decode(11).
    This is a candidate implementation until checked against a real device ID.
    """
    if properties.get("Z55") != b"2":
        raise ValueError("This check supports only the observed device-binding mode 2.")
    missing = {"MP", "R2", "11"} - properties.keys()
    if missing:
        raise ValueError("Missing metadata fields: " + ", ".join(sorted(missing)))
    if not re.fullmatch(r"[0-9a-fA-F]{16}", android_id):
        raise ValueError("Expected the 16 hexadecimal characters read by the app.")
    if len(properties["R2"]) != 32:
        raise ValueError("Expected a 32-byte HMAC-SHA256 tag in R2.")
    key = hashlib.sha256(properties["MP"] + android_id.encode("ascii") + b"/hou5Pa9htsf").digest()
    return hmac.compare_digest(hmac.digest(key, properties["11"], "sha256"), properties["R2"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path, help="App-generated Properties file")
    parser.add_argument("--verify-android-id", action="store_true",
                        help="Prompt privately for one app-specific Android ID and check its HMAC")
    args = parser.parse_args(argv)
    try:
        properties = read_properties(args.backup)
        report = inspect_backup(properties)
        if args.verify_android_id:
            android_id = getpass.getpass("Android ID read by the original app: ").strip()
            matches = verify_android_id(properties, android_id)
            report["metadata_hmac_matches"] = matches
            print(json.dumps(report, indent=2))
            return 0 if matches else 1
        print(json.dumps(report, indent=2))
        return 0
    except (OSError, ValueError, EOFError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
