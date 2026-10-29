import base64
import contextlib
import hashlib
import hmac
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from mobilepasser.android_import import (
    PINLESS_DEFAULT, ImportedToken, decrypt_backup, main as import_main, parse_ssaid_xml,
    read_android_backup, write_config,
)
from mobilepasser.mobilepasser import main
from mobilepasser.utils.token_generation import generate_token_from_key


class AndroidImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.backup = Path(self.temp.name) / "backup.properties"
        self.output = Path(self.temp.name) / "imported.cfg"
        self.android_id = "0123456789abcdef"
        self.secret = bytes(range(32))
        self.policy = "377991174847"
        self.properties = self.make_fixture()
        self.save_fixture()

    def save_fixture(self):
        self.backup.write_text("\n".join(
            f"{key}={base64.b64encode(value).decode().replace('=', chr(92) + '=')}"
            for key, value in self.properties.items()
        ), encoding="ascii")

    def make_fixture(self, password=PINLESS_DEFAULT):
        name = b"Test token"
        binding = self.android_id.encode()
        p = {key: key.encode() * 32 for key in ("FR", "MP", "ML", "G7", "TS", "W5")}
        p.update({key: bytes(range(16)) for key in ("69", "GQ", "53", "BV")})
        p["Z55"] = b"2"

        def encrypt(data, key, iv, padded):
            if padded:
                padder = PKCS7(128).padder()
                data = padder.update(data) + padder.finalize()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            return cipher.update(data) + cipher.finalize()

        def derived(salt, suffix):
            return hashlib.sha256(p[salt] + binding + suffix).digest()

        def wrap_key(salt, suffix):
            salt_hash = hashlib.sha256(p[salt] + suffix + binding + name).digest()
            return hashlib.pbkdf2_hmac("sha256", password, salt_hash, 1000, 32)

        metadata = b"Z7=" + base64.b64encode(self.policy.encode()) + b"\nZ16=MTIsMCwwLDA=\n"
        p["11"] = encrypt(metadata, derived("FR", b"vY?401cws1B("), p["69"], True)
        p["R2"] = hmac.digest(derived("MP", b"/hou5Pa9htsf"), p["11"], "sha256")
        p["Y1"] = encrypt(name, derived("ML", b"P0=2q|kExu8"), p["GQ"], True)
        p["Y2"] = hmac.digest(derived("G7", b"8)x@umLSg"), p["Y1"], "sha256")
        wrapping = b"W" * 32
        p["BA"] = encrypt(wrapping, wrap_key("TS", b"--g23N56q}9y"), p["53"], False)
        p["B1"] = hmac.digest(wrap_key("W5", b"*vmJq$b]|n6012Duj"), p["BA"], "sha256")
        p["F3"] = encrypt(b"\x20" + self.secret + bytes(95), wrapping, p["BV"], False)
        return p

    def test_pinless_import_and_cli(self):
        original = self.backup.read_bytes()
        token = decrypt_backup(self.backup, self.android_id)
        self.assertEqual((token.name, token.policy, token.index, token.secret),
                         ("Test token", self.policy, 12, self.secret))
        write_config(token, self.output, 6)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = main(["-c", str(self.output)])
        self.assertEqual(result, 0)
        self.assertEqual(stdout.getvalue().strip(), generate_token_from_key(self.secret, 12))
        self.assertEqual(self.backup.read_bytes(), original)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertNotIn(self.secret.hex(), repr(token))

    def test_imported_index_update(self):
        write_config(decrypt_backup(self.backup, self.android_id), self.output, 6)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(main(["-c", str(self.output), "-a"]), 0)
            self.assertEqual(main(["-c", str(self.output)]), 0)
        self.assertEqual(stdout.getvalue().splitlines(), [
            generate_token_from_key(self.secret, 12), generate_token_from_key(self.secret, 13),
        ])

    def test_pin_import_preserves_leading_zeroes(self):
        pin = "00427190"
        self.properties = self.make_fixture(password=pin.encode())
        self.save_fixture()
        original = self.backup.read_bytes()
        token = decrypt_backup(self.backup, self.android_id, pin=pin)
        self.assertEqual(token.secret, self.secret)
        write_config(token, self.output, 6)
        self.assertNotIn(pin, self.output.read_text())
        self.assertEqual(self.backup.read_bytes(), original)
        for incorrect in (None, "wrong-pin", "427190", ""):
            with self.subTest(pin=incorrect), self.assertRaises(ValueError):
                decrypt_backup(self.backup, self.android_id, pin=incorrect)

    def test_pin_cli_prompts_without_echoing_or_saving_pin(self):
        pin = "00427190"
        self.properties = self.make_fixture(password=pin.encode())
        self.save_fixture()
        id_file = Path(self.temp.name) / "android-id"
        id_file.write_text(self.android_id)
        args = [str(self.backup), "--android-id-file", str(id_file),
                "--pin", "--otp-length", "6", "--output", str(self.output)]
        for supplied in ("wrong-pin", pin):
            stdout, stderr = io.StringIO(), io.StringIO()
            with self.subTest(correct=supplied == pin), \
                    patch("mobilepasser.android_import.getpass.getpass", return_value=supplied) as prompt, \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = import_main(args)
                self.assertEqual(result, 0 if supplied == pin else 1)
                prompt.assert_called_once_with("MobilePASS token PIN: ")
                self.assertNotIn(supplied, stdout.getvalue() + stderr.getvalue())
                self.assertEqual(self.output.exists(), supplied == pin)
        self.assertNotIn(pin, self.output.read_text())

    def test_wrong_device_and_tampering_rejected(self):
        with self.assertRaises(ValueError):
            decrypt_backup(self.backup, "fedcba9876543210")
        for key in ("11", "Y1", "BA", "F3"):
            with self.subTest(field=key):
                original = self.properties[key]
                self.properties[key] = bytes([original[0] ^ 1]) + original[1:]
                self.save_fixture()
                with self.assertRaises(ValueError):
                    decrypt_backup(self.backup, self.android_id)
                self.properties[key] = original

    def test_config_never_overwrites(self):
        self.output.write_text("existing config")
        with self.assertRaises(FileExistsError):
            write_config(ImportedToken("Test", self.policy, 12, self.secret), self.output, 6)
        self.assertEqual(self.output.read_text(), "existing config")

    def test_invalid_raw_key_rejected(self):
        with self.assertRaises(ValueError):
            generate_token_from_key(b"short", 12)

    def test_ssaid_selection_handles_multiple_xml_roots(self):
        xml = (b'<?xml version="1.0"?><settings><setting name="10007" value="0123456789abcdef"/>'
               b'<setting name="10008" value="fedcba9876543210"/></settings><namespaceHashes/>')
        self.assertEqual(parse_ssaid_xml(xml, 10007), self.android_id)
        with self.assertRaises(ValueError):
            parse_ssaid_xml(xml, 10009)

    def test_ssaid_duplicate_and_invalid_rejected(self):
        for xml in (b'<settings><setting name="10007" value="bad"/></settings>',
                    b'<settings><setting name="10007"/><setting name="10007"/></settings>'):
            with self.subTest(xml=xml), self.assertRaises(ValueError):
                parse_ssaid_xml(xml, 10007)

    def test_adb_file_auto_selection_and_in_memory_decryption(self):
        directory = "/data/user/0/securecomputing.devices.android.controller/app_SAFENET_TOKEN_MP3"
        name = "A" * 40
        listing = f"{directory}/{name}\n{directory}/notes.txt\n"
        with patch("mobilepasser.android_import._run_adb",
                   side_effect=[listing.encode(), self.backup.read_bytes()]) as adb:
            backup = read_android_backup(serial="device-id")
            token = decrypt_backup(backup, self.android_id)
        self.assertEqual(token.secret, self.secret)
        self.assertEqual(adb.call_count, 2)
        self.assertEqual(adb.call_args.args,
                         (["exec-out", "su", "-c", f"cat {directory}/{name}"], "device-id"))

    def test_adb_multiple_files_require_selection(self):
        directory = "/data/user/10/securecomputing.devices.android.controller/app_SAFENET_TOKEN_MP3"
        first, second = "A" * 40, "B" * 40
        listing = f"{directory}/{first}\n{directory}/{second}\n".encode()
        with patch("mobilepasser.android_import._run_adb", return_value=listing) as adb:
            with self.assertRaisesRegex(ValueError, "--token-file"):
                read_android_backup(user=10)
            adb.assert_called_once()
        with patch("mobilepasser.android_import._run_adb",
                   side_effect=[listing, self.backup.read_bytes()]) as adb:
            token = decrypt_backup(read_android_backup(user=10, token_file=second), self.android_id)
            self.assertEqual(token.secret, self.secret)
            self.assertEqual(adb.call_args.args[0][-1], f"cat {directory}/{second}")

    def test_adb_no_files_and_invalid_selection_do_not_read_files(self):
        directory = "/data/user/0/securecomputing.devices.android.controller/app_SAFENET_TOKEN_MP3"
        for listing, selected in ((b"", None),
                                  (f"{directory}/{'A' * 40}\n".encode(), "../settings_ssaid.xml")):
            with self.subTest(selected=selected), \
                    patch("mobilepasser.android_import._run_adb", return_value=listing) as adb:
                with self.assertRaises(ValueError):
                    read_android_backup(token_file=selected)
                adb.assert_called_once()

    def test_cli_can_import_both_file_and_id_from_adb(self):
        stdout = io.StringIO()
        with patch("mobilepasser.android_import.read_android_backup",
                   return_value=io.StringIO(self.backup.read_text())) as read_backup, \
                patch("mobilepasser.android_import.read_android_id",
                      return_value=self.android_id) as read_id, \
                contextlib.redirect_stdout(stdout):
            result = import_main(["--from-adb", "--serial", "device-id", "--user", "10",
                                  "--token-file", "A" * 40, "--otp-length", "6",
                                  "--output", str(self.output)])
        self.assertEqual(result, 0)
        read_backup.assert_called_once_with("device-id", 10, "A" * 40)
        read_id.assert_called_once_with("device-id", 10)
        self.assertIn(self.secret.hex(), self.output.read_text())
        self.assertNotIn(self.secret.hex(), stdout.getvalue())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_cli_rejects_missing_or_ambiguous_sources(self):
        common = ["--otp-length", "6", "--output", str(self.output)]
        for source in ([], [str(self.backup), "--token-file", "A" * 40],
                       [str(self.backup), "--from-adb", "--token-file", "A" * 40]):
            with self.subTest(source=source), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as error:
                import_main(common + source)
            self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
