"""Redaction and the secret-leak guard (docs/contract.md s7).

Nothing from a response is stored before it passes through here. Pattern redaction is a best
effort (it cannot know every secret shape); the leak guard is the backstop that knows the exact
credential values used in the run and refuses to write anything that still contains one.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from typing import Any, Final

from boundarycheck.model import Observation

BLOB_BODY_LIMIT: Final = 65_536
MIN_SECRET_LENGTH: Final = 8
SENSITIVE_HEADERS: Final = frozenset({"authorization", "proxy-authorization", "cookie", "set-cookie"})

_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_LONG = re.compile(r"[A-Za-z0-9+/_=-]{32,}")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


class RedactionError(Exception):
    """Redaction could not be completed; the evidence for that case must be discarded."""


class SecretLeakError(Exception):
    """A credential value was about to be written. The message never contains the value."""


class Redactor:
    def __init__(self, mask_fields: Iterable[str] = (), secrets: Iterable[str] = ()) -> None:
        self._mask = frozenset(mask_fields)
        self._secrets = sorted({s for s in secrets if len(s) >= MIN_SECRET_LENGTH}, key=len, reverse=True)

    def text(self, value: str) -> str:
        for secret in self._secrets:
            value = value.replace(secret, "[credential]")
        value = _JWT.sub("[redacted-jwt]", value)
        value = _EMAIL.sub("[redacted-email]", value)
        return _LONG.sub(lambda m: m.group(0) if _UUID.fullmatch(m.group(0)) else "[redacted-long-string]", value)

    def headers(self, headers: Mapping[str, str]) -> dict[str, str]:
        return {
            name: "[redacted]" if name.lower() in SENSITIVE_HEADERS else self.text(value)
            for name, value in headers.items()
        }

    def _walk(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: "[masked]" if k in self._mask else self._walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._walk(v) for v in value]
        if isinstance(value, str):
            return self.text(value)
        return value

    def body(self, body: bytes, content_type: str) -> str:
        decoded = body.decode("utf-8", errors="replace")
        if "json" in content_type.lower():
            try:
                parsed = json.loads(decoded)
            except ValueError:
                return self.text(decoded)
            return json.dumps(self._walk(parsed), sort_keys=True, ensure_ascii=True)
        return self.text(decoded)

    def observation(self, observation: Observation) -> dict[str, Any]:
        """The redacted, bounded blob that is stored (and hashed) as evidence."""
        content_type = next((v for k, v in observation.headers.items() if k.lower() == "content-type"), "")
        try:
            body = self.body(observation.body, content_type)
            headers = self.headers(observation.headers)
        except (ValueError, RecursionError) as exc:
            raise RedactionError(f"redaction failed ({type(exc).__name__})") from None
        return {
            "status": observation.status,
            "headers": headers,
            "body": body[:BLOB_BODY_LIMIT],
            "truncated": len(body) > BLOB_BODY_LIMIT or observation.error == "body_too_large",
            "error": observation.error,
        }


def assert_no_secrets(texts: Iterable[str], secrets: Iterable[str]) -> None:
    """Raise if any credential value occurs in any text. Empty and tiny values are ignored because
    they would match everything (they are not credentials)."""
    needles = [s for s in secrets if len(s) >= MIN_SECRET_LENGTH]
    if not needles:
        return
    haystack = list(texts)
    if any(n in t for n in needles for t in haystack):
        raise SecretLeakError("a credential value would have been written; nothing was stored")
