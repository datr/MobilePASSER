import configparser
import contextlib
import hashlib
import hmac
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from mobilepasser.mobilepasser import main
from mobilepasser.utils.activation_code import ActivationCode, InvalidActivationKey
from mobilepasser.utils.token_generation import (
    KDF1, generate_mobilepass_token, long_to_byte_array, truncated_value,
)


# Public sample key from examples/mobilepasser.cfg, never a personal credential.
LEGACY_KEY = "QVKYC-FM6KO-SY6F7-TR22W"
MODERN_KEY = "QVKYFM6KSY6FTR22AADI"


class TokenTests(unittest.TestCase):
    def test_legacy_tokens(self):
        # Independently calculated from the decoded entropy, SHA-256 KDF1 and HMAC.
        for index, expected in ((0, "374844"), (1, "124927"),
                                (2, "048405"), (256, "381723")):
            with self.subTest(index=index):
                self.assertEqual(generate_mobilepass_token(LEGACY_KEY, index), expected)

    def test_modern_key(self):
        self.assertFalse(ActivationCode(MODERN_KEY).legacy)
        self.assertEqual(generate_mobilepass_token(MODERN_KEY, 0), "374844")

    def test_modern_checksum_rejected(self):
        with self.assertRaises(InvalidActivationKey):
            ActivationCode(MODERN_KEY[:-1] + "J")

    def test_legacy_checksum_rejected(self):
        with self.assertRaises(InvalidActivationKey):
            ActivationCode(LEGACY_KEY[:-1] + "A")

    def test_lowercase_key(self):
        self.assertEqual(generate_mobilepass_token(LEGACY_KEY.lower(), 0), "374844")

    def test_policy(self):
        self.assertEqual(generate_mobilepass_token(LEGACY_KEY, 0, "policy"), "704457")
        self.assertEqual(generate_mobilepass_token(LEGACY_KEY, 0, "päss%word"), "204160")

    def test_length_and_leading_zero(self):
        self.assertEqual(generate_mobilepass_token(LEGACY_KEY, 2), "048405")
        self.assertEqual(generate_mobilepass_token(LEGACY_KEY, 2, length=8), "93048405")

    def test_invalid_parameters(self):
        for index, length in ((-1, 6), (2**64, 6), (0, 0), (0, -1)):
            with self.subTest(index=index, length=length), self.assertRaises(ValueError):
                generate_mobilepass_token(LEGACY_KEY, index, length=length)

    def test_counter_byte_order(self):
        self.assertEqual(long_to_byte_array(0x0102030405060708), bytes(range(1, 9)))

    def test_kdf_vector(self):
        self.assertEqual(
            KDF1(hashlib.sha256(), b"secret", b"", 0, 32).hex(),
            "4cb92a0e1786543d1ced7cf7a376bd787a6dfe42f1ed6218b3c1d1d38e25fa31",
        )

    def test_rfc4226_truncation(self):
        # Standard HOTP vectors exercise the shared dynamic truncation algorithm.
        expected = (755224, 287082, 359152, 969429, 338314,
                    254676, 287922, 162583, 399871, 520489)
        for counter, token in enumerate(expected):
            digest = hmac.new(b"12345678901234567890", counter.to_bytes(8, "big"), hashlib.sha1)
            self.assertEqual(truncated_value(digest.hexdigest()) % 10**6, token)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = Path(self.temp.name) / "mobilepasser.cfg"

    def run_cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = main(["-c", str(self.config), *args])
        return result, stdout.getvalue(), stderr.getvalue()

    def write_config(self, **values):
        config = configparser.ConfigParser(interpolation=None)
        config["MobilePASS"] = {"activation_key": LEGACY_KEY, **values}
        with self.config.open("w") as handle:
            config.write(handle)

    def test_missing_key(self):
        result, stdout, stderr = self.run_cli()
        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertIn("activation key", stderr)
        self.assertIn("secret_key", stderr)
        self.assertIn(str(self.config), stderr)
        self.assertIn("not found or unreadable", stderr)
        self.assertIn("--activation-key", stderr)
        self.assertIn("--config-file", stderr)

    def test_explicit_zero_and_empty_policy_override_config(self):
        self.write_config(index="12", policy="policy")
        self.assertEqual(self.run_cli("-x", "0", "-p", ""), (0, "374844\n", ""))

    def test_literal_percent_in_policy(self):
        self.write_config(policy="päss%word")
        self.assertEqual(self.run_cli(), (0, "204160\n", ""))

    def test_auto_update(self):
        self.write_config(index="1", auto_update_index="True")
        self.assertEqual(self.run_cli(), (0, "124927\n", ""))
        self.assertEqual(self.run_cli(), (0, "048405\n", ""))
        config = configparser.ConfigParser()
        config.read(self.config)
        self.assertEqual(config.getint("MobilePASS", "index"), 3)
        self.assertEqual(config.get("MobilePASS", "activation_key"), LEGACY_KEY)

    def test_update_creates_section(self):
        self.assertEqual(self.run_cli("-k", LEGACY_KEY, "-a"), (0, "374844\n", ""))
        config = configparser.ConfigParser()
        config.read(self.config)
        self.assertEqual(config.getint("MobilePASS", "index"), 1)

    def test_no_update_by_default(self):
        self.assertEqual(self.run_cli("-k", LEGACY_KEY), (0, "374844\n", ""))
        self.assertFalse(self.config.exists())

    def test_failure_does_not_update_index(self):
        self.write_config(index="4", auto_update_index="True")
        before = self.config.read_bytes()
        result, stdout, stderr = self.run_cli("-k", "invalid")
        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertIn("Invalid activation key", stderr)
        self.assertEqual(self.config.read_bytes(), before)

    def test_bad_config(self):
        self.write_config(index="not-a-number")
        result, stdout, stderr = self.run_cli()
        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr)

    def test_module_entry_point(self):
        result = subprocess.run(
            [sys.executable, "-m", "mobilepasser", "-c", str(self.config), "-k", LEGACY_KEY],
            cwd=self.temp.name, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "374844\n")


if __name__ == "__main__":
    unittest.main()
