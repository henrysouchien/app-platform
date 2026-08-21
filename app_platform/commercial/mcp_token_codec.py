"""One-time MCP bearer construction and versioned peppered digest verification."""

from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass, field
import hashlib
import hmac
import re
import secrets
from types import MappingProxyType
from typing import Callable, Mapping


TOKEN_SCHEME = "hank_pk"
DIGEST_VERSION = 1
PREFIX_ENTROPY_BYTES = 16
SECRET_ENTROPY_BYTES = 32
SALT_BYTES = 32
_TOKEN = re.compile(
    r"^hank_pk_([A-Za-z0-9_-]{22})_([A-Za-z0-9_-]{43})$"
)
_DOMAIN = b"hank:mcp-token:v1\x00"


def _b64url(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_b64url(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True, slots=True)
class McpTokenMaterial:
    token: str = field(repr=False)
    prefix: str
    salt: bytes
    digest: bytes
    digest_version: int
    pepper_version: int


class McpTokenPepperRing:
    """Explicit current/prior pepper keys; verification never guesses a version."""

    def __init__(self, *, active_version: int, peppers: Mapping[int, bytes]) -> None:
        if isinstance(active_version, bool) or not isinstance(active_version, int):
            raise ValueError("active MCP token pepper version must be an integer")
        normalized: dict[int, bytes] = {}
        for version, key in peppers.items():
            if isinstance(version, bool) or not isinstance(version, int):
                raise ValueError("MCP token pepper versions must be integers")
            if version in normalized:
                raise ValueError("MCP token pepper versions must be unique")
            if not isinstance(key, (bytes, bytearray)):
                raise ValueError("MCP token peppers must be bytes")
            normalized[version] = bytes(key)
        if active_version <= 0 or active_version not in normalized:
            raise ValueError("active MCP token pepper version is unavailable")
        if any(version <= 0 for version in normalized):
            raise ValueError("MCP token pepper versions must be positive")
        if any(len(key) < 32 for key in normalized.values()):
            raise ValueError("MCP token peppers require at least 256 bits")
        self._active_version = int(active_version)
        self._peppers = MappingProxyType(normalized)

    @property
    def active_version(self) -> int:
        return self._active_version

    @property
    def versions(self) -> frozenset[int]:
        return frozenset(self._peppers)

    def issue(
        self,
        *,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> McpTokenMaterial:
        def draw(size: int) -> bytes:
            value = random_bytes(size)
            if not isinstance(value, (bytes, bytearray)):
                raise ValueError("MCP token randomness source must return bytes")
            return bytes(value)

        prefix_bytes = draw(PREFIX_ENTROPY_BYTES)
        secret_bytes = draw(SECRET_ENTROPY_BYTES)
        salt = draw(SALT_BYTES)
        if (
            len(prefix_bytes) != PREFIX_ENTROPY_BYTES
            or len(secret_bytes) != SECRET_ENTROPY_BYTES
            or len(salt) != SALT_BYTES
        ):
            raise ValueError("MCP token randomness source returned the wrong byte count")
        prefix = _b64url(prefix_bytes)
        secret = _b64url(secret_bytes)
        token = f"{TOKEN_SCHEME}_{prefix}_{secret}"
        digest = self._digest(
            prefix=prefix,
            secret=secret,
            salt=salt,
            digest_version=DIGEST_VERSION,
            pepper_version=self._active_version,
        )
        return McpTokenMaterial(
            token=token,
            prefix=prefix,
            salt=salt,
            digest=digest,
            digest_version=DIGEST_VERSION,
            pepper_version=self._active_version,
        )

    def parse_prefix(self, token: str) -> str | None:
        match = _TOKEN.fullmatch(token)
        return None if match is None else match.group(1)

    def verify(
        self,
        token: str,
        *,
        expected_prefix: str,
        salt: bytes,
        expected_digest: bytes,
        digest_version: int,
        pepper_version: int,
    ) -> bool:
        match = _TOKEN.fullmatch(token)
        if match is None:
            self._dummy_compare(token)
            return False
        prefix, secret = match.groups()
        if pepper_version not in self._peppers or digest_version != DIGEST_VERSION:
            self._dummy_compare(token)
            return False
        candidate = self._digest(
            prefix=prefix,
            secret=secret,
            salt=bytes(salt),
            digest_version=digest_version,
            pepper_version=pepper_version,
        )
        prefix_matches = hmac.compare_digest(prefix, expected_prefix)
        digest_matches = hmac.compare_digest(candidate, bytes(expected_digest))
        return prefix_matches and digest_matches

    def verify_unknown(self, token: str) -> bool:
        """Run the same keyed-digest/compare shape for an unknown indexed prefix."""

        self._dummy_compare(token)
        return False

    def _dummy_compare(self, token: str) -> None:
        match = _TOKEN.fullmatch(token)
        if match is None:
            prefix = _b64url(hashlib.sha256(token.encode("utf-8")).digest()[:16])
            secret = _b64url(hashlib.sha256(b"secret\x00" + token.encode("utf-8")).digest())
        else:
            prefix, secret = match.groups()
        candidate = self._digest(
            prefix=prefix,
            secret=secret,
            salt=b"\x00" * SALT_BYTES,
            digest_version=DIGEST_VERSION,
            pepper_version=self._active_version,
        )
        hmac.compare_digest(prefix, "A" * 22)
        hmac.compare_digest(candidate, b"\x00" * hashlib.sha256().digest_size)

    def _digest(
        self,
        *,
        prefix: str,
        secret: str,
        salt: bytes,
        digest_version: int,
        pepper_version: int,
    ) -> bytes:
        if digest_version != DIGEST_VERSION:
            raise ValueError("unsupported MCP token digest version")
        pepper = self._peppers.get(pepper_version)
        if pepper is None:
            raise ValueError("MCP token pepper version is unavailable")
        if len(salt) != SALT_BYTES:
            raise ValueError("MCP token salt must be 256 bits")
        if len(_decode_b64url(prefix)) != PREFIX_ENTROPY_BYTES:
            raise ValueError("MCP token prefix has invalid entropy")
        if len(_decode_b64url(secret)) != SECRET_ENTROPY_BYTES:
            raise ValueError("MCP token secret has invalid entropy")
        payload = (
            _DOMAIN
            + digest_version.to_bytes(2, "big")
            + salt
            + prefix.encode("ascii")
            + b"\x00"
            + secret.encode("ascii")
        )
        return hmac.new(pepper, payload, hashlib.sha256).digest()


__all__ = [
    "DIGEST_VERSION",
    "McpTokenMaterial",
    "McpTokenPepperRing",
    "PREFIX_ENTROPY_BYTES",
    "SALT_BYTES",
    "SECRET_ENTROPY_BYTES",
    "TOKEN_SCHEME",
]
