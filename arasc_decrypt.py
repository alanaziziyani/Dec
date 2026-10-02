# arasc_decrypt.py
# -*- coding: utf-8 -*-
"""
Decrypt .arasc files (ArasClient / ARASC container).

Container layout:
    "ARASC" (5B) | version(1B: 1 or 2) | flags(1B) | body
    flags bit0 = passwordProtected

If passwordProtected:
    body = Layer2 (AES-256-GCM, PBKDF2-SHA256 with embedded iteration count)

Layer1 (always present) is base64-encoded when passwordProtected,
otherwise the raw body.

Layer1 layout:
    salt(16) | nonce(12) | uint32_be(ct_len) | ciphertext+tag(16)
    key = PBKDF2-SHA256("ArasClient-ARASC-L1-Key-v1-obfus", salt,
                        250000 (v2) | 60000 (v1), 32)

Layer1 plaintext = gzip(JSON payload) || random padding
"""
import base64
import json
import re
import struct
import zlib
from typing import Optional, List, Dict, Any
from urllib.parse import quote as _urlquote

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ---------- Constants ----------
MAGIC = b"ARASC"
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
FLAG_PASSWORD = 0x01

L1_KEY = b"ArasClient-ARASC-L1-Key-v1-obfus"
L1_ITER_V2 = 250_000
L1_ITER_V1 = 60_000


# ---------- Exceptions ----------
class ArascError(Exception):
    pass


class ArascNotArasc(ArascError):
    pass


class ArascUnsupportedVersion(ArascError):
    pass


class ArascPasswordRequired(ArascError):
    pass


class ArascPasswordWrong(ArascError):
    pass


class ArascCorrupted(ArascError):
    pass


class ArascEmpty(ArascError):
    pass


# ---------- Crypto helpers ----------
def _pbkdf2(password: bytes, salt: bytes, iterations: int, dklen: int = 32) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=dklen,
        salt=salt,
        iterations=iterations,
    ).derive(password)


def _gunzip_prefix(data: bytes) -> bytes:
    """Decompress a gzip stream, ignoring trailing padding."""
    d = zlib.decompressobj(wbits=31)
    out = d.decompress(data)
    out += d.flush()
    return out


# ---------- Header ----------
def peek_arasc(data: bytes) -> Dict[str, Any]:
    """Peek at header without decrypting."""
    if not data or len(data) < 7:
        raise ArascNotArasc("File too short")
    if data[:5] != MAGIC:
        raise ArascNotArasc("Not an .arasc file (bad magic)")
    version = data[5]
    if version not in (1, 2):
        raise ArascUnsupportedVersion(f"Unsupported version: {version}")
    flags = data[6]
    return {
        "version": version,
        "flags": flags,
        "password_protected": bool(flags & FLAG_PASSWORD),
    }


# ---------- Layer decryption ----------
def _decrypt_layer1(blob: bytes, version: int) -> bytes:
    min_len = SALT_LEN + NONCE_LEN + 4 + TAG_LEN
    if len(blob) < min_len:
        raise ArascCorrupted("Layer1 blob too short")
    salt = blob[0:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN + NONCE_LEN]
    off = SALT_LEN + NONCE_LEN
    (length,) = struct.unpack(">I", blob[off:off + 4])
    ct_start = off + 4
    ct = blob[ct_start:ct_start + length]
    if len(ct) != length:
        raise ArascCorrupted("Layer1 truncated")
    iters = L1_ITER_V2 if version >= 2 else L1_ITER_V1
    key = _pbkdf2(L1_KEY, salt, iters, 32)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception as e:
        raise ArascCorrupted(f"Layer1 decrypt failed: {e}") from e


def _decrypt_layer2(blob: bytes, password: str) -> bytes:
    min_len = 4 + SALT_LEN + NONCE_LEN + 4 + TAG_LEN
    if len(blob) < min_len:
        raise ArascCorrupted("Layer2 blob too short")
    (iters,) = struct.unpack(">I", blob[0:4])
    if iters <= 0 or iters > 5_000_000:
        raise ArascCorrupted(f"Invalid PBKDF2 iterations: {iters}")
    salt = blob[4:4 + SALT_LEN]
    nonce = blob[4 + SALT_LEN:4 + SALT_LEN + NONCE_LEN]
    off = 4 + SALT_LEN + NONCE_LEN
    (length,) = struct.unpack(">I", blob[off:off + 4])
    off += 4
    ct = blob[off:off + length]
    if len(ct) != length:
        raise ArascCorrupted("Layer2 truncated")
    key = _pbkdf2(password.encode("utf-8"), salt, iters, 32)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception as e:
        raise ArascPasswordWrong("Wrong password") from e


# ---------- Main decrypt ----------
def decrypt_arasc(data: bytes, password: Optional[str] = None) -> bytes:
    """
    Decrypt .arasc, return the JSON payload bytes (UTF-8).
    Raises ArascPasswordRequired if file is password-protected and
    password is None.
    """
    header = peek_arasc(data)
    version = header["version"]
    body = data[7:]

    if header["password_protected"]:
        if not password:
            raise ArascPasswordRequired("Password required")
        body = _decrypt_layer2(body, password)

    # body is now Base64 (ASCII) of the Layer1 blob
    try:
        l1_blob = base64.b64decode(body.strip(), validate=False)
    except Exception as e:
        raise ArascCorrupted(f"Base64 decode failed: {e}") from e

    gzipped = _decrypt_layer1(l1_blob, version)

    try:
        plaintext = _gunzip_prefix(gzipped)
    except Exception as e:
        raise ArascCorrupted(f"gunzip failed: {e}") from e

    if not plaintext:
        raise ArascEmpty("Empty payload")
    return plaintext


# ---------- Payload → URI extraction (best effort) ----------
# Note: enum values guessed from ArasClient conventions.
# If some links fail to build, JSON output still contains everything.
_CFG = {
    "VMESS": 1, "VLESS": 2, "SHADOWSOCKS": 3, "SOCKS": 4, "HTTP": 5,
    "TROJAN": 6, "WIREGUARD": 7, "HYSTERIA2": 8, "ANYTLS": 9,
    "AMNEZIAWG": 10, "AETHER": 11, "MIERU": 12, "CUSTOM": 13,
    "POLICYGROUP": 14, "PROXYCHAIN": 15,
}


def _guess_kind(p: dict) -> Optional[str]:
    """Infer config type from field presence."""
    if not isinstance(p, dict):
        return None
    ct = p.get("configType")
    # Try explicit configType first
    for name, val in _CFG.items():
        if ct == val:
            return name
    # Fallback heuristics
    if p.get("flow") or p.get("publicKey"):
        return "VLESS"
    if p.get("method"):
        return "SHADOWSOCKS"
    if p.get("privateKey") or p.get("peerPublicKey"):
        return "WIREGUARD"
    if p.get("password") and not p.get("uuid"):
        return "TROJAN"
    return None


def _common_qs(p: dict) -> str:
    parts = []
    net = p.get("network") or "tcp"
    sec = p.get("security") or "none"
    parts.append(f"type={net}")
    parts.append(f"security={sec}")
    for key, url in (("sni", "sni"), ("fingerPrint", "fp"),
                     ("alpn", "alpn"), ("host", "host"), ("path", "path")):
        v = p.get(key)
        if v:
            parts.append(f"{url}={_urlquote(str(v), safe='')}")
    ht = p.get("headerType")
    if ht and ht != "none":
        parts.append(f"headerType={ht}")
    if p.get("insecure"):
        parts.append("allowInsecure=1")
    return "&".join(parts)


def profile_to_link(profile: dict) -> Optional[str]:
    if not isinstance(profile, dict):
        return None
    server = profile.get("server") or ""
    port = profile.get("serverPort")
    if not server or not port:
        return None
    port = str(port)
    remarks = profile.get("remarks") or "config"
    tag = _urlquote(remarks, safe="")

    kind = _guess_kind(profile)

    if kind == "VLESS":
        uuid = profile.get("password") or profile.get("uuid") or ""
        if not uuid:
            return None
        q = _common_qs(profile)
        flow = profile.get("flow")
        if flow:
            q += f"&flow={_urlquote(flow, safe='')}"
        pbk = profile.get("publicKey")
        if pbk:
            q += f"&pbk={_urlquote(pbk, safe='')}"
        sid = profile.get("shortId")
        if sid:
            q += f"&sid={_urlquote(sid, safe='')}"
        return f"vless://{uuid}@{server}:{port}?{q}#{tag}"

    if kind == "SHADOWSOCKS":
        method = profile.get("method") or ""
        password = profile.get("password") or ""
        userinfo = base64.urlsafe_b64encode(
            f"{method}:{password}".encode("utf-8")
        ).decode().rstrip("=")
        return f"ss://{userinfo}@{server}:{port}#{tag}"

    if kind == "TROJAN":
        pw = profile.get("password") or ""
        if not pw:
            return None
        q = _common_qs(profile)
        return f"trojan://{_urlquote(pw, safe='')}@{server}:{port}?{q}#{tag}"

    if kind == "VMESS":
        uuid = profile.get("password") or profile.get("uuid") or ""
        if not uuid:
            return None
        # Build v2rayN-style vmess JSON link
        vm = {
            "v": "2", "ps": remarks, "add": server, "port": port,
            "id": uuid, "aid": str(profile.get("alterId", 0)),
            "scy": profile.get("security", "auto"),
            "net": profile.get("network", "tcp"),
            "type": profile.get("headerType", "none"),
            "host": profile.get("host", ""),
            "path": profile.get("path", ""),
            "tls": profile.get("streamSecurity", ""),
            "sni": profile.get("sni", ""),
        }
        blob = base64.urlsafe_b64encode(
            json.dumps(vm, separators=(",", ":")).encode("utf-8")
        ).decode().rstrip("=")
        return f"vmess://{blob}"

    return None


def extract_arasc_links(payload: Any) -> List[str]:
    """Extract all shareable URIs from an ArascPayload dict."""
    links: List[str] = []
    if not isinstance(payload, dict):
        return links

    for sub in payload.get("subscriptions", []) or []:
        for cfg in sub.get("configs", []) or []:
            profile = (cfg or {}).get("profile") or {}
            link = profile_to_link(profile)
            if link:
                links.append(link)

    # Also try to catch any raw URIs embedded in the JSON
    try:
        raw = json.dumps(payload, ensure_ascii=False)
        for m in re.finditer(
            r'((?:vless|vmess|trojan|ss|socks|hysteria2?|tuic)://[^\s"\'<>]+)',
            raw, re.IGNORECASE,
        ):
            links.append(m.group(1))
    except Exception:
        pass

    # Dedup, preserve order
    seen = set()
    out = []
    for l in links:
        if l not in seen:
            seen.add(l)
            out.append(l)
    return out


def summarize_payload(payload: Any) -> str:
    """Short human-readable summary."""
    if not isinstance(payload, dict):
        return "payload is not a dict"
    subs = payload.get("subscriptions", []) or []
    total = sum(len(s.get("configs", []) or []) for s in subs)
    return (
        f"formatVersion={payload.get('formatVersion')} "
        f"subscriptions={len(subs)} configs={total} "
        f"subLinks={len(payload.get('subLinks', []) or [])} "
        f"note={payload.get('note')!r}"
    )
