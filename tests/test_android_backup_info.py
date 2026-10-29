import base64
from pathlib import Path
import tempfile
import unittest

from tools.android_backup_info import inspect_backup, read_properties, verify_android_id


class AndroidBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "token.properties"

    def test_java_properties_escaping_and_continuation(self):
        self.path.write_text("# comment\nZ55=Mg\\=\\=\n11=dGVz\\\n  dA\\=\\=\n", encoding="ascii")
        self.assertEqual(read_properties(self.path), {"Z55": b"2", "11": b"test"})

    def test_invalid_values_rejected(self):
        for content in ("11=%%%\n", "11=AA==\n11=AA==\n", "11=AA\\", "11=AA\\n==\n"):
            with self.subTest(content=content):
                self.path.write_text(content)
                with self.assertRaises(ValueError):
                    read_properties(self.path)

    def test_report_does_not_include_values(self):
        properties = {"Z55": b"2", "11": b"sensitive ciphertext", "unknown": b"secret"}
        report = inspect_backup(properties)
        self.assertEqual(report["binding_mode"], "2")
        self.assertEqual(report["fields"]["11"]["bytes"], 20)
        self.assertNotIn("sensitive", str(report))
        self.assertNotIn("secret", str(report))

    def fixture(self):
        # Synthetic vector independently computed using the OpenSSL CLI.
        return {
            "Z55": b"2", "MP": b"A" * 64, "11": b"test" * 80,
            "R2": bytes.fromhex("40882b3d342b1ba6a900f04063f7f5f74304bbf33e5c36fbce4cf06cabf8e53c"),
        }

    def test_android_id_hmac_vector(self):
        self.assertTrue(verify_android_id(self.fixture(), "0123456789abcdef"))
        self.assertFalse(verify_android_id(self.fixture(), "0123456789abcdee"))

    def test_modified_ciphertext_rejected(self):
        properties = self.fixture()
        properties["11"] += b"tampered"
        self.assertFalse(verify_android_id(properties, "0123456789abcdef"))

    def test_invalid_binding_inputs_rejected(self):
        for changes in ({"Z55": b"1"}, {"R2": b"short"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                verify_android_id({**self.fixture(), **changes}, "0123456789abcdef")
        with self.assertRaises(ValueError):
            verify_android_id(self.fixture(), "bad ID")
        with self.assertRaises(ValueError):
            verify_android_id({"Z55": b"2"}, "0123456789abcdef")

    def test_read_only_inspection(self):
        self.path.write_text("\n".join(
            f"{name}={base64.b64encode(value).decode()}" for name, value in self.fixture().items()
        ))
        original = self.path.read_bytes()
        properties = read_properties(self.path)
        self.assertTrue(verify_android_id(properties, "0123456789abcdef"))
        inspect_backup(properties)
        self.assertEqual(self.path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
