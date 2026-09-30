# zsx_decrypt.py
"""
ZedSecure .zsx v2 decryptor + format auto-detector.
Compatible with the cipher used by dev.cluvex.zedsecure.crypto.ZsxCrypto.
"""
import base64
import hashlib
import json
import re
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

MAGIC = b"ZSX1"
OPEN_KEY = hashlib.sha256(b"ZedSecure .zsx v2").digest()
CFG_AAD = b"zsx-cfg-v1"

URL_RE = re.compile(
    r'(?:vless|vmess|trojan|ss|ssr|hysteria2?|tuic|socks5?|wireguard|wg|juicity|'
    r'happ|zedsecure)://[^\s"\'<>`]+',
    re.IGNORECASE,
)


# ---------------- exceptions ----------------
class ZsxError(Exception):
    pass

class ZsxTamperError(ZsxError):
    pass

class ZsxLegacyError(ZsxError):
    pass

class ZsxExpiredError(ZsxError):
    pass

class ZsxPasswordRequired(ZsxError):
    pass

class ZsxPasswordWrong(ZsxError):
    pass


# ---------------- internals ----------------
def _b64d(s: str) -> bytes:
    s = s.strip()
    s += "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.b64decode(s)
    except Exception:
        return base64.urlsafe_b64decode(s)


def _now_ms() -> int:
    return int(time.time() * 1000)


def read_inner(data: bytes) -> dict:
    if len(data) < len(MAGIC) + 1:
        raise ZsxTamperError("file too short")
    if data[:len(MAGIC)] != MAGIC:
        raise ZsxTamperError("invalid magic")

    version = data[len(MAGIC)]
    if version == 1:
        raise ZsxLegacyError("older ZedSecure version")
    if version != 2:
        raise ZsxTamperError(f"unsupported .zsx version {version}")
    if len(data) < len(MAGIC) + 1 + 12:
        raise ZsxTamperError("file too short for nonce")

    i = len(MAGIC) + 1
    nonce = data[i:i + 12]
    ct = data[i + 12:]
    aad = MAGIC + bytes([version])

    try:
        inner_bytes = AESGCM(OPEN_KEY).decrypt(nonce, ct, aad)
    except Exception:
        raise ZsxTamperError("outer AEAD failed")

    try:
        return json.loads(inner_bytes)
    except Exception:
        raise ZsxTamperError("inner JSON invalid")


def peek_zsx(data: bytes) -> dict:
    inner = read_inner(data)
    return {
        "passwordProtected": inner.get("mode") == 1,
        "mode": inner.get("mode"),
        "nameEn": inner.get("nameEn"),
        "nameFa": inner.get("nameFa"),
        "note": inner.get("note"),
        "createdAt": inner.get("createdAt"),
        "expiresAt": inner.get("expiresAt"),
        "kdf": inner.get("kdf"),
    }


def decrypt_zsx(data: bytes, password: str = None) -> bytes:
    inner = read_inner(data)

    expires = inner.get("expiresAt")
    if expires is not None and int(expires) < _now_ms():
        raise ZsxExpiredError("این کانفیگ منقضی شده است")

    mode = inner.get("mode", 0)
    if mode == 0:
        key = OPEN_KEY
    elif mode == 1:
        if not password:
            raise ZsxPasswordRequired("A password is required")
        kdf = inner.get("kdf") or {}
        salt = _b64d(kdf["salt"])
        key = hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=int(kdf.get("iterations", 3)),
            memory_cost=int(kdf.get("memKiB", 65536)),
            parallelism=int(kdf.get("parallelism", 1)),
            hash_len=32,
            type=Type.ID,
            version=19,
        )
    else:
        raise ZsxTamperError("unknown mode")

    cfg_nonce = _b64d(inner["cfgNonce"])
    cfg_cipher = _b64d(inner["cfgCipher"])
    try:
        return AESGCM(key).decrypt(cfg_nonce, cfg_cipher, CFG_AAD)
    except Exception:
        if mode == 1:
            raise ZsxPasswordWrong("Incorrect password")
        raise ZsxTamperError("config AEAD failed")


# ---------------- format detection ----------------
def extract_links(text: str):
    links = URL_RE.findall(text)
    return [l.rstrip(',\\]})"\'').strip() for l in links]


def try_parse_structured(content: bytes, _depth: int = 0):
    """
    Detect the shape of the decrypted payload.
    Returns dict with keys:
        kind : 'urls' | 'json' | 'xml' | 'base64' | 'text' | 'binary'
        links: list of URL strings
        json : parsed json (or None)
        text : decoded text (or None)
    """
    out = {"kind": "binary", "links": [], "json": None, "text": None}
    if _depth > 4:
        return out

    # 1. try UTF-8
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        try:
            decoded = base64.b64decode(content, validate=False)
            text = decoded.decode("utf-8")
            out["kind"] = "base64"
            content = decoded
        except Exception:
            return out

    text = text.strip()

    # 2. direct URLs
    urls = extract_links(text)
    if urls:
        out["text"] = text
        out["links"] = urls
        if out["kind"] != "base64":
            out["kind"] = "urls"
        return out

    # 3. JSON
    if text[:1] in "{[":
        try:
            out["json"] = json.loads(text)
            out["text"] = text
            out["kind"] = "json"
            out["links"] = extract_links(text)
            return out
        except Exception:
            pass

    # 4. whole body looks like base64 (skip if we're already decoded)
    if out["kind"] != "base64" and len(text) > 20 and re.fullmatch(r'[A-Za-z0-9+/=_\-\s]+', text):
        try:
            decoded = _b64d(text)
            sub = try_parse_structured(decoded, _depth + 1)
            if sub["kind"] in ("urls", "json", "xml"):
                sub["kind"] = "base64"
                return sub
        except Exception:
            pass

    # 5. XML
    if text.startswith("<?xml") or text.startswith("<"):
        out["kind"] = "xml"
        out["text"] = text
        return out

    out["kind"] = "text"
    out["text"] = text
    return out


# ---------------- CLI ----------------
if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else input("ZSX file path: ").strip().strip('"')
    with open(path, "rb") as f:
        data = f.read()

    meta = peek_zsx(data)
    print("--- metadata ---")
    print(json.dumps(meta, indent=2, ensure_ascii=False))

    pwd = input("Password: ") if meta["passwordProtected"] else None
    plain = decrypt_zsx(data, pwd)
    parsed = try_parse_structured(plain)
    print(f"\n--- kind: {parsed['kind']} ({len(plain)} bytes) ---")
    if parsed["links"]:
        for l in parsed["links"]:
            print(l)
    elif parsed["text"]:
        print(parsed["text"])
