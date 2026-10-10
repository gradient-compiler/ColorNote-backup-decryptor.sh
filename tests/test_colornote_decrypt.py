"""Tests for colornote_decrypt.py. Run with: python3 -m unittest discover tests"""
import hashlib
import json
import os
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import colornote_decrypt as cd  # noqa: E402

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # encryption for fixtures needs the cryptography package
    Cipher = None

RECORDS = [
    {"_id": 1, "title": "Groceries", "note": "[V] eggs\n[ ] milk 🥛\n", "type": 16, "color_index": 4,
     "active_state": 0, "space": 0, "encrypted": 0},
    {"_id": 2, "title": "Work", "note": json.dumps({"folder_id": 99}), "type": 128, "active_state": 256},
    {"_id": 3, "title": "Old", "note": "archived", "type": 0, "space": 16, "active_state": 0, "encrypted": 0},
    {"_id": 4, "title": "", "note": "", "type": 0, "active_state": 32},
    {"_id": 5, "title": "syncable_settings", "note": "{}", "type": 256, "active_state": 256},
]


def make_backup(records, password):
    plain = struct.pack(">II", 2, len(records))
    for r in records:
        b = json.dumps(r, ensure_ascii=False).encode()
        plain += struct.pack(">I", len(b)) + b
    pad = 16 - len(plain) % 16
    key = hashlib.md5(password.encode() + cd.FIXED_SALT).digest()
    enc = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
    return b"\x00N\x00O\x00T\x00E" + bytes(20) + enc.update(plain + bytes([pad]) * pad) + enc.finalize()


@unittest.skipIf(Cipher is None, "needs the cryptography package to build fixtures")
class DecryptTests(unittest.TestCase):
    def test_round_trip(self):
        records = cd.decrypt_backup(make_backup(RECORDS, "s3cret"), "s3cret")
        self.assertEqual(records, RECORDS)
        self.assertIn("2 notes", cd.summarize(records))

    def test_wrong_password(self):
        with self.assertRaises(cd.DecryptError):
            cd.decrypt_backup(make_backup(RECORDS, "s3cret"), "0000")

    def test_pure_python_aes_matches(self):
        key, iv, data = os.urandom(16), os.urandom(16), os.urandom(160)
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ct = enc.update(data) + enc.finalize()
        self.assertEqual(cd._aes128_cbc_decrypt_pure(key, iv, ct), data)

    def test_cli_writes_notes_and_folders(self):
        tmp = Path(self._testMethodName + ".backup")
        out = tmp.with_suffix(".json")
        try:
            tmp.write_bytes(make_backup(RECORDS, "0000"))
            self.assertEqual(cd.main([str(tmp), "-p", "0000", "-o", str(out)]), 0)
            titles = [r["title"] for r in json.loads(out.read_text(encoding="utf-8"))]
            self.assertEqual(titles, ["Groceries", "Work", "Old"])
        finally:
            tmp.unlink(missing_ok=True)
            out.unlink(missing_ok=True)


class PlainJsonTests(unittest.TestCase):
    def test_accepts_already_decrypted_json(self):
        self.assertEqual(cd.load_any(json.dumps(RECORDS).encode(), None), RECORDS)
        lines = "\n".join(json.dumps(r) for r in RECORDS[:2]).encode()
        self.assertEqual(cd.load_any(lines, None), RECORDS[:2])


if __name__ == "__main__":
    unittest.main()
