#!/usr/bin/env python3
"""One-step ColorNote backup decryptor.

Decrypts a ColorNote ``.backup``/``.dat``/``.doc`` file and writes clean JSON
in a single command: no Java, no fixup scripts, no manual clean-up.

    python3 colornote_decrypt.py colornote-20260128.backup            # prompts for password
    python3 colornote_decrypt.py backup.backup -p 0000 -o notes.json
    python3 colornote_decrypt.py backup.backup --all                  # keep settings/folders/trash too

Only the Python standard library is required. If the ``cryptography`` package
is installed it is used for AES (faster); otherwise a built-in pure-Python AES
decryptor is used.

Format (reverse engineered, see README):
  * 28-byte plaintext header (UTF-16 "NOTE", version, timestamp, ...).
  * Remainder is AES-128-CBC, PKCS#7 padded, IV = 16 zero bytes.
  * key = MD5(password + "ColorNote Fixed Salt")  (OpenSSL EVP_BytesToKey, 1 round).
  * Plaintext is a sequence of sections ``[u32 id][u32 count]`` each followed
    by ``count`` records ``[u32 byte length][UTF-8 JSON object]`` (big endian).
Older backups (no header) are handled by also trying offset 0 and falling back
to scanning the plaintext for JSON objects.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import struct
import sys
from pathlib import Path

FIXED_SALT = b"ColorNote Fixed Salt"
HEADER_OFFSETS = (28, 0)

# ColorNote record field values.
TYPE_TEXT, TYPE_CHECKLIST, TYPE_FOLDER, TYPE_SETTINGS = 0, 16, 128, 256
STATE_ACTIVE, STATE_TRASHED, STATE_DELETED = 0, 16, 32
SPACE_ARCHIVED = 16
COLORS = {1: "red", 2: "orange", 3: "yellow", 4: "green", 5: "blue",
          6: "purple", 7: "black", 8: "gray", 9: "white"}


class DecryptError(Exception):
    pass


# --------------------------------------------------------------------------- AES

def _build_tables():
    sbox = [0] * 256
    p = q = 1
    while True:  # standard multiplicative-inverse + affine transform construction
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ ((q << 1 | q >> 7) & 0xFF) ^ ((q << 2 | q >> 6) & 0xFF) \
            ^ ((q << 3 | q >> 5) & 0xFF) ^ ((q << 4 | q >> 4) & 0xFF)
        sbox[p] = x ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


_SBOX, _INV_SBOX = _build_tables()


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _mul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


_M9, _M11, _M13, _M14 = ([_mul(i, k) for i in range(256)] for k in (9, 11, 13, 14))


def _expand_key(key: bytes) -> list[list[int]]:
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(words[i - 1])
        if i % 4 == 0:
            t = [_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        words.append([a ^ b for a, b in zip(words[i - 4], t)])
    return [sum(words[r * 4:r * 4 + 4], []) for r in range(11)]


def _decrypt_block(block: bytes, rk: list[list[int]]) -> bytes:
    s = [b ^ k for b, k in zip(block, rk[10])]
    for rnd in range(9, -1, -1):
        # inverse shift rows (column-major state)
        s = [s[(i + 4 * (i % 4) * 3) % 16] for i in range(16)]
        s = [_INV_SBOX[b] for b in s]
        s = [b ^ k for b, k in zip(s, rk[rnd])]
        if rnd:
            out = []
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                out += [_M14[a0] ^ _M11[a1] ^ _M13[a2] ^ _M9[a3],
                        _M9[a0] ^ _M14[a1] ^ _M11[a2] ^ _M13[a3],
                        _M13[a0] ^ _M9[a1] ^ _M14[a2] ^ _M11[a3],
                        _M11[a0] ^ _M13[a1] ^ _M9[a2] ^ _M14[a3]]
            s = out
    return bytes(s)


def _aes128_cbc_decrypt_pure(key: bytes, iv: bytes, data: bytes) -> bytes:
    rk = _expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(_decrypt_block(block, rk), prev))
        prev = block
    return bytes(out)


def aes128_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return _aes128_cbc_decrypt_pure(key, iv, data)
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return d.update(data) + d.finalize()


# --------------------------------------------------------------------- decryption

def derive_key(password: str) -> bytes:
    return hashlib.md5(password.encode("utf-8") + FIXED_SALT).digest()


def _strip_pkcs7(data: bytes) -> bytes | None:
    if not data:
        return None
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        return None
    return data[:-n]


def parse_sections(plain: bytes) -> list[dict] | None:
    """Strict parser for the length-prefixed layout. Returns None if it doesn't fit."""
    records, i = [], 0
    try:
        while i < len(plain):
            if i + 8 > len(plain):
                return None
            _section, count = struct.unpack_from(">II", plain, i)
            i += 8
            for _ in range(count):
                (length,) = struct.unpack_from(">I", plain, i)
                i += 4
                if i + length > len(plain):
                    return None
                obj = json.loads(plain[i:i + length].decode("utf-8"))
                if not isinstance(obj, dict):
                    return None
                records.append(obj)
                i += length
    except (struct.error, ValueError):
        return None
    return records


def scan_json_objects(plain: bytes) -> list[dict]:
    """Lenient fallback: find every top-level JSON object in a blob of bytes."""
    text = plain.decode("utf-8", errors="replace")
    decoder = json.JSONDecoder()
    records, i = [], 0
    while True:
        i = text.find("{", i)
        if i < 0:
            return records
        try:
            obj, end = decoder.raw_decode(text, i)
        except ValueError:
            i += 1
            continue
        if isinstance(obj, dict):
            records.append(obj)
        i = end


def decrypt_backup(raw: bytes, password: str) -> list[dict]:
    key = derive_key(password)
    for offset in HEADER_OFFSETS:
        body = raw[offset:]
        if not body or len(body) % 16:
            continue
        plain = _strip_pkcs7(aes128_cbc_decrypt(key, bytes(16), body))
        if plain is None:
            continue
        records = parse_sections(plain) or scan_json_objects(plain)
        if records:
            return records
    raise DecryptError("Could not decrypt backup - wrong password? "
                       "(If you never set a master password in ColorNote, use 0000.)")


def load_any(raw: bytes, password: str | None) -> list[dict]:
    """Accept an encrypted backup, or JSON that was already decrypted by older tools."""
    stripped = raw.lstrip()
    if stripped[:1] in (b"[", b"{"):
        try:
            data = json.loads(stripped)
            return data if isinstance(data, list) else data.get("notes", [data])
        except ValueError:
            return scan_json_objects(stripped)
    if password is None:
        password = getpass.getpass("ColorNote master password (0000 if never set): ") or "0000"
    return decrypt_backup(raw, password)


def is_user_note(rec: dict) -> bool:
    return (rec.get("type") in (TYPE_TEXT, TYPE_CHECKLIST)
            and rec.get("active_state", 0) in (STATE_ACTIVE, STATE_TRASHED)
            and "note" in rec)


def summarize(records: list[dict]) -> str:
    notes = [r for r in records if is_user_note(r)]
    count = lambda pred: sum(1 for r in notes if pred(r))
    return (f"{len(notes)} notes "
            f"({count(lambda r: r.get('type') == TYPE_CHECKLIST)} checklists, "
            f"{count(lambda r: r.get('space') == SPACE_ARCHIVED)} archived, "
            f"{count(lambda r: r.get('active_state') == STATE_TRASHED)} in trash, "
            f"{count(lambda r: r.get('encrypted'))} locked), "
            f"{sum(1 for r in records if r.get('type') == TYPE_FOLDER)} folders")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("backup", type=Path, help="ColorNote backup file (.backup/.dat/.doc)")
    ap.add_argument("-p", "--password", help="master password (prompted if omitted; default 0000)")
    ap.add_argument("-o", "--output", type=Path, help="output JSON (default: <backup>.json)")
    ap.add_argument("--all", action="store_true",
                    help="keep every record (settings, folders, deleted) instead of only notes")
    args = ap.parse_args(argv)

    try:
        records = load_any(args.backup.read_bytes(), args.password)
    except (OSError, DecryptError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    out_records = records if args.all else [
        r for r in records if is_user_note(r) or r.get("type") == TYPE_FOLDER]
    output = args.output or args.backup.with_suffix(args.backup.suffix + ".json")
    output.write_text(json.dumps(out_records, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Decrypted {summarize(records)} -> {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
