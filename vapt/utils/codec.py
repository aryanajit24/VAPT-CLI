
from __future__ import annotations

import base64
import binascii
import hashlib
import html as _html
import json
import math
import re
import urllib.parse


HASH_PATTERNS: list[tuple[str, str]] = [
    ("MD5", r"^[a-f0-9]{32}$"),
    ("SHA-1", r"^[a-f0-9]{40}$"),
    ("SHA-256", r"^[a-f0-9]{64}$"),
    ("SHA-384", r"^[a-f0-9]{96}$"),
    ("SHA-512", r"^[a-f0-9]{128}$"),
    ("NTLM", r"^[a-f0-9]{32}$"),
    ("MySQL 4.x", r"^[a-f0-9]{16}$"),
    ("MySQL 5.x", r"^\*[A-F0-9]{40}$"),
    ("bcrypt", r"^\$2[ayb]\$.{56}$"),
    ("SHA-512 Crypt", r"^\$6\$.{0,16}\$[./A-Za-z0-9]{86}$"),
    ("SHA-256 Crypt", r"^\$5\$.{0,16}\$[./A-Za-z0-9]{43}$"),
    ("MD5 Crypt", r"^\$1\$.{0,8}\$[./A-Za-z0-9]{22}$"),
    ("Argon2", r"^\$argon2(i|d|id)\$"),
    ("CRC-32", r"^[a-f0-9]{8}$"),
]


class Codec:


    @staticmethod
    def encode_base64(data: str) -> str:
        return base64.b64encode(data.encode()).decode()

    @staticmethod
    def decode_base64(data: str) -> str:
        cleaned = data.strip()
        padding = 4 - len(cleaned) % 4
        if padding != 4:
            cleaned += "=" * padding
        try:
            return base64.b64decode(cleaned).decode("utf-8", errors="replace")
        except Exception:
            return base64.urlsafe_b64decode(cleaned).decode("utf-8", errors="replace")


    @staticmethod
    def encode_url(data: str) -> str:
        return urllib.parse.quote(data, safe="")

    @staticmethod
    def decode_url(data: str) -> str:
        return urllib.parse.unquote(data)

    @staticmethod
    def encode_url_all(data: str) -> str:
        return "".join(f"%{ord(c):02X}" for c in data)


    @staticmethod
    def encode_hex(data: str) -> str:
        return data.encode().hex()

    @staticmethod
    def decode_hex(data: str) -> str:
        cleaned = data.strip().replace(" ", "").replace("0x", "").replace("\\x", "")
        return bytes.fromhex(cleaned).decode("utf-8", errors="replace")


    @staticmethod
    def encode_html(data: str) -> str:
        return _html.escape(data, quote=True)

    @staticmethod
    def decode_html(data: str) -> str:
        return _html.unescape(data)

    @staticmethod
    def encode_html_numeric(data: str) -> str:
        return "".join(f"&#{ord(c)};" for c in data)


    @staticmethod
    def encode_unicode_escape(data: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in data)

    @staticmethod
    def decode_unicode_escape(data: str) -> str:
        return data.encode("raw_unicode_escape").decode("unicode_escape")


    @staticmethod
    def decode_jwt(token: str) -> dict:
        parts = token.strip().split(".")
        if len(parts) not in (2, 3):
            raise ValueError(f"Invalid JWT: expected 2-3 parts, got {len(parts)}")
        result = {}
        for idx, name in enumerate(["header", "payload", "signature"]):
            if idx >= len(parts):
                break
            if idx < 2:
                padded = parts[idx] + "=" * (4 - len(parts[idx]) % 4)
                raw = base64.urlsafe_b64decode(padded)
                result[name] = json.loads(raw)
            else:
                result[name] = parts[idx]
        return result

    @staticmethod
    def encode_jwt_part(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


    @staticmethod
    def hash_string(data: str, algorithm: str = "sha256") -> str:
        algos = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha384": hashlib.sha384,
            "sha512": hashlib.sha512,
        }
        if algorithm not in algos:
            raise ValueError(f"Unknown algorithm: {algorithm}. Use: {list(algos)}")
        return algos[algorithm](data.encode()).hexdigest()

    @staticmethod
    def identify_hash(hash_str: str) -> list[str]:
        normalized = hash_str.strip()
        matches = []
        for name, pattern in HASH_PATTERNS:
            if re.match(pattern, normalized, re.IGNORECASE):
                matches.append(name)
        return matches if matches else ["Unknown"]


    @staticmethod
    def entropy(data: str) -> float:
        if not data:
            return 0.0
        freq: dict[str, int] = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length) for count in freq.values()
        )


    @staticmethod
    def smart_decode(data: str) -> dict[str, object]:
        results: dict[str, object] = {}
        stripped = data.strip()

        try:
            padded = stripped + "=" * (4 - len(stripped) % 4)
            decoded = base64.b64decode(padded).decode("utf-8")
            if decoded.isprintable() and len(decoded) > 0:
                results["base64"] = decoded
        except Exception:
            pass

        url_decoded = urllib.parse.unquote(stripped)
        if url_decoded != stripped:
            results["url"] = url_decoded

        try:
            cleaned_hex = stripped.replace("0x", "").replace(" ", "")
            hex_decoded = bytes.fromhex(cleaned_hex).decode("utf-8")
            if hex_decoded.isprintable() and len(hex_decoded) > 0:
                results["hex"] = hex_decoded
        except Exception:
            pass

        html_decoded = _html.unescape(stripped)
        if html_decoded != stripped:
            results["html"] = html_decoded

        if stripped.count(".") == 2:
            try:
                results["jwt"] = Codec.decode_jwt(stripped)
            except Exception:
                pass

        hash_ids = Codec.identify_hash(stripped)
        if hash_ids != ["Unknown"]:
            results["hash_type"] = hash_ids

        return results


    @staticmethod
    def test_regex(pattern: str, text: str, flags: int = 0) -> dict:
        try:
            compiled = re.compile(pattern, flags)
        except re.error as exc:
            return {"valid": False, "error": str(exc)}

        matches = []
        for m in compiled.finditer(text):
            matches.append({
                "match": m.group(),
                "start": m.start(),
                "end": m.end(),
                "groups": list(m.groups()),
            })
        return {"valid": True, "pattern": pattern, "match_count": len(matches), "matches": matches}


    @classmethod
    def encode_all(cls, data: str) -> dict[str, str]:
        return {
            "base64": cls.encode_base64(data),
            "url": cls.encode_url(data),
            "url_all": cls.encode_url_all(data),
            "hex": cls.encode_hex(data),
            "html": cls.encode_html(data),
            "html_numeric": cls.encode_html_numeric(data),
            "unicode": cls.encode_unicode_escape(data),
            "md5": cls.hash_string(data, "md5"),
            "sha1": cls.hash_string(data, "sha1"),
            "sha256": cls.hash_string(data, "sha256"),
        }
