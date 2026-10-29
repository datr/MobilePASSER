"""Import the inspected MobilePASS Android storage format without changing Android."""

import argparse
import configparser
from dataclasses import dataclass, field
import getpass
import hashlib
import hmac
import io
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import xml.etree.ElementTree as ET

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from .android_backup import read_properties, verify_android_id


PACKAGE = "securecomputing.devices.android.controller"
# Recovered from the inspected APK, not a personal PIN.
PINLESS_DEFAULT = b"234hqxw6MMtgwed"


@dataclass(repr=False)
class ImportedToken:
    name: str
    policy: str
    index: int
    secret: bytes = field(repr=False)


def _aes_decrypt(ciphertext, key, iv, padded):
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    if padded:
        unpadder = PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()
    return plaintext


def decrypt_backup(backup, android_id, pin=None):
    """Decrypt the secret using a token PIN or the app's pinless default."""
    if pin == "":
        raise ValueError("Token PIN must not be empty.")
    password = PINLESS_DEFAULT if pin is None else pin.encode("utf-8")
    properties = read_properties(backup)
    if not verify_android_id(properties, android_id):
        raise ValueError("Device binding does not match the backup metadata HMAC.")
    required = {"FR", "69", "ML", "G7", "Y1", "Y2", "GQ", "W5", "TS", "BA", "B1", "53", "F3", "BV"}
    if required - properties.keys():
        raise ValueError("Backup is missing fields required for import.")
    binding = android_id.encode("ascii")

    def derived(salt, suffix):
        return hashlib.sha256(properties[salt] + binding + suffix).digest()

    name_tag = hmac.digest(derived("G7", b"8)x@umLSg"), properties["Y1"], "sha256")
    if not hmac.compare_digest(name_tag, properties["Y2"]):
        raise ValueError("Token-label integrity check failed.")
    name = _aes_decrypt(properties["Y1"], derived("ML", b"P0=2q|kExu8"), properties["GQ"], True)
    metadata = _aes_decrypt(properties["11"], derived("FR", b"vY?401cws1B("), properties["69"], True)
    # The decrypted metadata uses the same ASCII/Base64 Properties representation.
    inner = read_properties_text(metadata.decode("ascii"))
    try:
        policy = inner["Z7"].decode("ascii")
        counters = [int(value) for value in inner["Z16"].decode("ascii").split(",")]
        index = counters[0]
    except (KeyError, ValueError, IndexError) as error:
        raise ValueError("Unsupported token metadata or counter representation.") from error
    if not 0 <= index < 2**64:
        raise ValueError("Stored token counter is out of range.")

    def wrapping_key(salt, suffix):
        salt_hash = hashlib.sha256(properties[salt] + suffix + binding + name).digest()
        return hashlib.pbkdf2_hmac("sha256", password, salt_hash, 1000, 32)

    expected_tag = hmac.digest(wrapping_key("W5", b"*vmJq$b]|n6012Duj"), properties["BA"], "sha256")
    if not hmac.compare_digest(expected_tag, properties["B1"]):
        if pin is None:
            raise ValueError("Wrapping-key HMAC mismatch; retry with --pin if the token requires a PIN. "
                             "A different APK format can also cause this error.")
        raise ValueError("Token PIN verification failed, or the backup uses a different APK format.")
    wrapping = _aes_decrypt(properties["BA"], wrapping_key("TS", b"--g23N56q}9y"), properties["53"], False)
    envelope = _aes_decrypt(properties["F3"], wrapping, properties["BV"], False)
    if len(envelope) != 128 or envelope[0] != 32 or any(envelope[33:]):
        raise ValueError("Unsupported secret envelope; expected a padded 32-byte OTP key.")
    return ImportedToken(name.decode("utf-8"), policy, index, envelope[1:33])


def read_properties_text(text):
    # Reuse the parser without writing decrypted metadata to disk.
    return read_properties(io.StringIO(text))


def write_config(token, destination, length):
    """Create a private config exclusively; existing files are never overwritten."""
    if not 1 <= length <= 8:
        raise ValueError("OTP length must be between 1 and 8.")
    config = configparser.ConfigParser(interpolation=None)
    config["MobilePASS"] = {
        "secret_key": token.secret.hex(),
        "index": str(token.index),
        "otp_length": str(length),
        "auto_update_index": "False",
        "android_policy": token.policy,
    }
    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        config.write(handle)


def parse_ssaid_xml(data, uid):
    # Android Settings files can contain multiple top-level XML elements.
    text = re.sub(r"<\?xml[^?]*\?>", "", data.decode("utf-8"))
    root = ET.fromstring("<document>" + text + "</document>")
    matches = [setting for setting in root.iter("setting") if setting.get("name") == str(uid)]
    if len(matches) != 1:
        raise ValueError("Expected one SSAID entry for the MobilePASS UID.")
    value = matches[0].get("value", "")
    if not re.fullmatch(r"[0-9a-fA-F]{16}", value):
        raise ValueError("The app SSAID is missing or malformed.")
    return value


def _run_adb(arguments, serial=None):
    adb = ["adb"] + (["-s", serial] if serial else [])
    result = subprocess.run(adb + arguments, capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError("ADB operation failed; check the connection and grant root to ADB on the device.")
    return result.stdout


def read_android_id(serial=None, user=0):
    """Read only the target app's SSAID using an already-authorized rooted device."""
    packages = _run_adb(["shell", "cmd", "package", "list", "packages", "-U",
                         "--user", str(user), PACKAGE], serial).decode()
    match = re.search(r"^package:" + re.escape(PACKAGE) + r"\s+uid:(\d+)\s*$", packages, re.MULTILINE)
    if not match:
        raise ValueError("MobilePASS was not found for the selected Android user.")
    path = f"/data/system/users/{user}/settings_ssaid.xml"
    data = _run_adb(["exec-out", "su", "-c", "cat " + path], serial)
    if data.startswith(b"ABX\x00"):
        data = _run_adb(["exec-out", "su", "-c", "abx2xml " + path + " -"], serial)
    return parse_ssaid_xml(data, int(match[1]))


def read_android_backup(serial=None, user=0, token_file=None):
    """Read one token Properties file into memory without writing Android data."""
    if user < 0:
        raise ValueError("Android user must be nonnegative.")
    directory = PurePosixPath(f"/data/user/{user}/{PACKAGE}/app_SAFENET_TOKEN_MP3")
    listing = _run_adb(["exec-out", "su", "-c",
                        f"find {shlex.quote(str(directory))} -maxdepth 1 -type f"], serial)
    # This app names its token files with the uppercase SHA1 of the token name.
    files = sorted({PurePosixPath(line).name for line in listing.decode("utf-8").splitlines()
                    if PurePosixPath(line).parent == directory
                    and re.fullmatch(r"[A-Fa-f0-9]{40}", PurePosixPath(line).name)})
    if not files:
        raise ValueError(f"No token Properties files found in {directory}.")
    if token_file is not None:
        if token_file not in files:
            raise ValueError("Unknown token file. Available files: " + ", ".join(files))
        selected = token_file
    elif len(files) == 1:
        selected = files[0]
    else:
        raise ValueError("Multiple token files found; select one with --token-file NAME: "
                         + ", ".join(files))
    data = _run_adb(["exec-out", "su", "-c", "cat " + shlex.quote(str(directory / selected))], serial)
    return io.StringIO(data.decode("ascii"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path, nargs="?",
                        help="Local Properties file; omit with --from-adb to read it from Android")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--otp-length", type=int, required=True,
                        help="OTP digits from the Android token policy")
    parser.add_argument("--pin", action="store_true",
                        help="Prompt privately for the Android token PIN (used only during import)")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--from-adb", action="store_true",
                        help="Read the app SSAID and, if no local backup is given, its Properties file over ADB")
    source.add_argument("--android-id-file", type=Path, help="Read an existing private SSAID file")
    parser.add_argument("--serial", help="ADB device serial")
    parser.add_argument("--user", type=int, default=0)
    parser.add_argument("--token-file", help="Token filename in app_SAFENET_TOKEN_MP3 (for direct ADB import)")
    args = parser.parse_args(argv)
    if args.backup is None and not args.from_adb:
        parser.error("provide a local backup file or use --from-adb")
    if args.token_file is not None and (not args.from_adb or args.backup is not None):
        parser.error("--token-file requires --from-adb without a local backup file")
    try:
        if args.user < 0:
            raise ValueError("Android user must be nonnegative.")
        if args.output.expanduser().exists():
            raise ValueError("Output already exists; select a new file.")
        backup = args.backup
        if args.from_adb:
            if backup is None:
                backup = read_android_backup(args.serial, args.user, args.token_file)
            android_id = read_android_id(args.serial, args.user)
        elif args.android_id_file:
            android_id = args.android_id_file.read_text(encoding="ascii").strip()
        else:
            android_id = getpass.getpass("Android ID read by the original app: ").strip()
        pin = getpass.getpass("MobilePASS token PIN: ") if args.pin else None
        token = decrypt_backup(backup, android_id, pin=pin)
        write_config(token, args.output, args.otp_length)
    except (OSError, ValueError, KeyError, UnicodeError, ET.ParseError, EOFError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(f"Imported key and stored counter into {args.output.expanduser()}. Android data was not changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
