"""Streaming, producer-side redaction for target-control output."""

from __future__ import annotations

import re
from typing import Iterable

from .common import TargetError


# Escape sequences are removed before C0/C1 controls.  An incomplete sequence
# consumes the rest of its record: treating it as terminal data could expose an
# OSC payload after the ESC byte itself is stripped.
_ANSI_RE = re.compile(
    r"(?:"
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b[PX^_][\s\S]*?\x1b\\"
    r"|\x1b[^\[\]PX^_]"
    r")"
)
_UNTERMINATED_ESCAPE_RE = re.compile(r"\x1b(?:\][\s\S]*|\[[\s\S]*|[PX^_][\s\S]*|[\s\S]?)$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_URL_USERINFO_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]*://)[^/?#\s@]+@")
_BEARER_RE = re.compile(r"(?i)\bbearer[ \t]+[^\s,;]+")
_CREDENTIAL_LABELS = (
    "api_key",
    "api-key",
    "access_token",
    "refresh_token",
    "token",
    "secret",
    "password",
    "passwd",
    "authorization",
)
_CREDENTIAL_LABEL_PATTERN = "|".join(re.escape(label) for label in _CREDENTIAL_LABELS)
_CREDENTIAL_RE = re.compile(
    rf"(?i)\b(?:{_CREDENTIAL_LABEL_PATTERN}|bearer)\s*(?:=|:)\s*(?:bearer\s+)?[^\s,;]+"
)
_TOKEN_SIGNATURE_RE = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{8,}|sk-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"
)
_IPV6_RE = re.compile(
    r"(?i)(?<![0-9a-f:])(?:"
    r"(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|"
    r"(?:[0-9a-f]{1,4}:){1,7}:[0-9a-f]{1,4}|"
    r"::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?"
    r")(?![0-9a-f:])"
)
_IPV4_RE = re.compile(
    r"(?<![0-9.])(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(?![0-9.])"
)
_HOME_RE = re.compile(
    r"(?:(?:/home|/Users)/[A-Za-z0-9._-]+(?:/[^\s\x00-\x1f\x7f]*)*|"
    r"~[A-Za-z0-9._-]*(?:/[^\s\x00-\x1f\x7f]*)*)"
)
_MAX_PENDING_LINE = 4_096
_REDACTED = "[REDACTED]"
_REDACTED_OVERSIZE = "[REDACTED_OVERSIZE]"
_REDACTED_HOME = "[REDACTED_HOME]"
_REDACTED_ADDRESS = "[REDACTED_ADDRESS]"
_TRUNCATED = "[TRUNCATED]"


class StreamingRedactor:
    """Redact output as bounded, independently safe line records.

    ``feed`` accepts ``str`` or UTF-8 ``bytes`` (invalid byte sequences are
    replaced).  It retains an incomplete record and emits only records ending
    in LF; CRLF is normalized to LF.  A record that exceeds ``max_pending`` is
    represented by one marker and ignored through its terminating LF.
    """

    __slots__ = (
        "_buffer",
        "_discarding",
        "_emitted",
        "_finalized",
        "_max_output",
        "_max_pending",
        "_pending_cr",
        "_secret_re",
        "_truncated",
    )

    def __init__(
        self,
        secrets: Iterable[str | bytes] = (),
        *,
        max_output: int = 65_536,
        max_pending: int = _MAX_PENDING_LINE,
    ) -> None:
        self._max_output = self._valid_limit(max_output, "redaction_limit_invalid")
        self._max_pending = self._valid_limit(max_pending, "redaction_pending_limit_invalid")

        known: list[str] = []
        try:
            iterator = iter(secrets)
        except TypeError:
            raise TargetError("redaction_secret_invalid", "redaction secret is invalid") from None
        for secret in iterator:
            if isinstance(secret, bytes):
                item = secret.decode("utf-8", "replace")
            elif isinstance(secret, str):
                item = secret
            else:
                raise TargetError("redaction_secret_invalid", "redaction secret is invalid")
            if "\n" in item or "\r" in item:
                raise TargetError("redaction_secret_invalid", "redaction secret is invalid")
            if item:
                known.append(item)
        known_secrets = tuple(sorted(set(known), key=len, reverse=True))
        self._secret_re = (
            re.compile("|".join(re.escape(secret) for secret in known_secrets)) if known_secrets else None
        )
        self._buffer = ""
        self._discarding = False
        self._emitted = 0
        self._finalized = False
        self._pending_cr = False
        self._truncated = False

    def __repr__(self) -> str:
        return (
            "StreamingRedactor("
            f"max_output={self._max_output}, max_pending={self._max_pending}, "
            f"finalized={self._finalized})"
        )

    @staticmethod
    def _valid_limit(value: int, code: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise TargetError(code, "redaction limit is invalid")
        return value

    @staticmethod
    def _decode(chunk: str | bytes) -> str:
        if isinstance(chunk, str):
            return chunk
        if isinstance(chunk, bytes):
            return chunk.decode("utf-8", "replace")
        raise TargetError("redaction_chunk_invalid", "redaction input is invalid")

    def _bounded(self, text: str) -> str:
        """Return only whole UTF-8 code points within the output byte budget."""

        if not text or self._truncated:
            return ""
        remaining = self._max_output - self._emitted
        encoded = text.encode("utf-8")
        if len(encoded) <= remaining:
            self._emitted += len(encoded)
            return text
        self._truncated = True
        marker_bytes = _TRUNCATED.encode("utf-8")
        reserve = len(marker_bytes) if remaining >= len(marker_bytes) else 0
        budget = remaining - reserve
        prefix: list[str] = []
        used = 0
        for character in text:
            size = len(character.encode("utf-8"))
            if used + size > budget:
                break
            prefix.append(character)
            used += size
        result = "".join(prefix)
        if reserve:
            result += _TRUNCATED
            used += reserve
        self._emitted += used
        return result

    def _redact_line(self, text: str) -> str:
        text = _ANSI_RE.sub("", text)
        text = _UNTERMINATED_ESCAPE_RE.sub("", text)
        if self._secret_re is not None:
            text = self._secret_re.sub(_REDACTED, text)
        text = _URL_USERINFO_RE.sub(r"\1[REDACTED]@", text)
        text = _CREDENTIAL_RE.sub(_REDACTED, text)
        text = _BEARER_RE.sub(_REDACTED, text)
        text = _TOKEN_SIGNATURE_RE.sub(_REDACTED, text)
        text = _HOME_RE.sub(_REDACTED_HOME, text)
        text = _IPV6_RE.sub(_REDACTED_ADDRESS, text)
        text = _IPV4_RE.sub(_REDACTED_ADDRESS, text)
        return _CONTROL_RE.sub("", text)

    def _emit_line(self, text: str, *, terminated: bool) -> str:
        if self._truncated:
            return ""
        if self._emitted >= self._max_output:
            self._truncated = True
            return ""
        suffix = "\n" if terminated else ""
        return self._bounded(self._redact_line(text) + suffix)

    def _emit_oversize(self) -> str:
        return self._bounded(_REDACTED_OVERSIZE)

    @staticmethod
    def _append_output(output: list[str], text: str) -> None:
        if text:
            output.append(text)


    def _finish_pending_cr(self, text: str, offset: int, output: list[str]) -> int:
        """Resolve a CR held at the end of a prior chunk."""

        if not self._pending_cr:
            return offset
        self._pending_cr = False
        if offset < len(text) and text[offset] == "\n":
            self._append_output(output, self._emit_line(self._buffer, terminated=True))
            self._buffer = ""
            return offset + 1
        if len(self._buffer) >= self._max_pending:
            self._buffer = ""
            self._discarding = True
            self._append_output(output, self._emit_oversize())
            return offset
        self._buffer += "\r"
        return offset

    def feed(self, chunk: str | bytes) -> str:
        """Accept a producer chunk and return only complete safe records."""

        if self._finalized:
            raise TargetError("redaction_finalized", "redactor is already finalized")
        text = self._decode(chunk)
        output: list[str] = []
        offset = 0

        while offset < len(text):
            if self._discarding:
                newline = text.find("\n", offset)
                if newline < 0:
                    break
                self._discarding = False
                self._append_output(output, self._bounded("\n"))
                offset = newline + 1
                continue

            offset = self._finish_pending_cr(text, offset, output)
            if self._discarding:
                continue
            if offset >= len(text):
                break

            newline = text.find("\n", offset)
            if newline < 0:
                end = len(text)
                held_cr = text.endswith("\r")
                content_end = end - 1 if held_cr else end
                content_length = len(self._buffer) + content_end - offset
                if content_length > self._max_pending:
                    self._buffer = ""
                    self._discarding = True
                    self._append_output(output, self._emit_oversize())
                else:
                    self._buffer += text[offset:content_end]
                    self._pending_cr = held_cr
                break

            content_end = newline - 1 if newline > offset and text[newline - 1] == "\r" else newline
            content_length = len(self._buffer) + content_end - offset
            if content_length > self._max_pending:
                self._buffer = ""
                self._append_output(output, self._emit_oversize())
                self._append_output(output, self._bounded("\n"))
            else:
                self._buffer += text[offset:content_end]
                self._append_output(output, self._emit_line(self._buffer, terminated=True))
                self._buffer = ""
            offset = newline + 1

        return "".join(output)

    def finalize(self) -> str:
        """Redact the final bounded unterminated record once."""

        if self._finalized:
            return ""
        self._finalized = True
        if self._discarding:
            self._buffer = ""
            self._discarding = False
            self._pending_cr = False
            return ""
        # A trailing CR cannot form a CRLF once finalization starts.  It is an
        # unsafe control character and will not be visible, so retaining it is
        # unnecessary and would needlessly consume pending-line capacity.
        self._pending_cr = False
        result = self._emit_line(self._buffer, terminated=False)
        self._buffer = ""
        return result


def redact_text(
    value: str | bytes,
    *,
    secrets: Iterable[str | bytes] = (),
    max_output: int = 65_536,


    max_pending: int = _MAX_PENDING_LINE,
) -> str:
    """Redact complete text using the same bounded line-record rules."""

    redactor = StreamingRedactor(secrets, max_output=max_output, max_pending=max_pending)
    return redactor.feed(value) + redactor.finalize()


# A concise spelling for producer code that only has one complete string.
redact = redact_text
REMOTE_REDACTION_EXTENSION = r'''
import codecs as _targetctl_codecs, os as _targetctl_os, re as _targetctl_re
_targetctl_ansi=_targetctl_re.compile(r'(?:\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[PX^_][\s\S]*?\x1b\\|\x1b[^\[\]PX^_])')
_targetctl_unterminated=_targetctl_re.compile(r'\x1b(?:\][\s\S]*|\[[\s\S]*|[PX^_][\s\S]*|[\s\S]?)$')
_targetctl_url=_targetctl_re.compile(r'\b([A-Za-z][A-Za-z0-9+.-]*://)[^/?#\s@]+@')
_targetctl_bearer=_targetctl_re.compile(r'(?i)\bbearer[ \t]+[^\s,;]+')
_targetctl_credential=_targetctl_re.compile(r'(?i)\b(?:api_key|api-key|access_token|refresh_token|token|secret|password|passwd|authorization|bearer)\s*(?:=|:)\s*(?:bearer\s+)?[^\s,;]+')
_targetctl_token=_targetctl_re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9_]{8,}|sk-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b')
_targetctl_ipv6=_targetctl_re.compile(r'(?i)(?<![0-9a-f:])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:[0-9a-f]{1,4}|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?)(?![0-9a-f:])')
_targetctl_ipv4=_targetctl_re.compile(r'(?<![0-9.])(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(?![0-9.])')
_targetctl_home=_targetctl_re.compile(r'(?:(?:/home|/Users)/[A-Za-z0-9._-]+(?:/[^\s\x00-\x1f\x7f]*)*|~[A-Za-z0-9._-]*(?:/[^\s\x00-\x1f\x7f]*)*)')
def _targetctl_redactor(secrets):
    values=set()
    for item in secrets:
        if isinstance(item,str):
            for candidate in (item,_targetctl_os.path.basename(item)):
                if 4<=len(candidate.encode('utf-8'))<=512: values.add(candidate)
    return {'secrets':tuple(sorted(values,key=len,reverse=True)),'buffer':'','discard':False,'out':bytearray(),'full':False,'decoder':_targetctl_codecs.getincrementaldecoder('utf-8')('replace')}
def _targetctl_append(state,text):
    if state['full'] or not text: return
    encoded=text.encode('utf-8'); remaining=1048576-len(state['out'])
    if len(encoded)<=remaining: state['out'].extend(encoded); return
    marker=b'[TRUNCATED]'; budget=remaining-len(marker) if remaining>=len(marker) else remaining; used=0; prefix=[]
    for character in text:
        size=len(character.encode('utf-8'))
        if used+size>budget: break
        prefix.append(character); used+=size
    state['out'].extend(''.join(prefix).encode('utf-8'))
    if remaining>=len(marker): state['out'].extend(marker)
    state['full']=True
def _targetctl_clean(state,text):
    text=_targetctl_ansi.sub('',text); text=_targetctl_unterminated.sub('',text)
    for secret in state['secrets']: text=text.replace(secret,'[REDACTED]')
    text=_targetctl_url.sub(r'\1[REDACTED]@',text)
    text=_targetctl_credential.sub('[REDACTED]',text)
    text=_targetctl_bearer.sub('[REDACTED]',text)
    text=_targetctl_token.sub('[REDACTED]',text)
    text=_targetctl_home.sub('[REDACTED_HOME]',text)
    text=_targetctl_ipv6.sub('[REDACTED_ADDRESS]',text)
    text=_targetctl_ipv4.sub('[REDACTED_ADDRESS]',text)
    return ''.join(character for character in text if character=='\n' or not (ord(character)<32 or 127<=ord(character)<160))
def _targetctl_redact_feed(state,chunk,final=False):
    text=state['decoder'].decode(chunk,final)
    for character in text:
        if state['discard']:
            if character=='\n': state['discard']=False; _targetctl_append(state,'\n')
            continue
        if character=='\n':
            _targetctl_append(state,_targetctl_clean(state,state['buffer'])+'\n'); state['buffer']=''; continue
        state['buffer']+=character
        if len(state['buffer'].encode('utf-8'))>4096:
            state['buffer']=''; state['discard']=True; _targetctl_append(state,'[REDACTED_OVERSIZE]')
    if final and not state['discard']:
        _targetctl_append(state,_targetctl_clean(state,state['buffer'])); state['buffer']=''
'''
