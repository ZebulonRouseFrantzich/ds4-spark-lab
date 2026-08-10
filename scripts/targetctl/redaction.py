"""Streaming, producer-side redaction for target-control output."""

from __future__ import annotations

import codecs
import re
from typing import Iterable

from .common import TargetError
from .config import _MAX_REMOTE_PATH_DEPTH, _MAX_REMOTE_PATH_LENGTH


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
# Each producer has at most two validated private runtime paths plus three
# fixed invocation values (controller/work/run identity).  A depth-N path
# contributes its full spelling, basename, and N-2 nontrivial ancestors: at
# most N canaries.  These formulae deliberately overbound aggregate bytes
# without ever shortening a canary.
MAX_REDACTION_PRIVATE_PATHS = 2
MAX_REDACTION_ADDITIONAL_SECRETS = 3
MAX_REDACTION_SECRET_BYTES = _MAX_REMOTE_PATH_LENGTH
MAX_REDACTION_SECRETS = (
    MAX_REDACTION_PRIVATE_PATHS * _MAX_REMOTE_PATH_DEPTH
    + MAX_REDACTION_ADDITIONAL_SECRETS
)
MAX_REDACTION_SECRET_AGGREGATE_BYTES = (
    MAX_REDACTION_SECRETS * MAX_REDACTION_SECRET_BYTES
)
_REDACTED = "[REDACTED]"
_REDACTED_OVERSIZE = "[REDACTED_OVERSIZE]"
_REDACTED_HOME = "[REDACTED_HOME]"
_REDACTED_ADDRESS = "[REDACTED_ADDRESS]"
_TRUNCATED = "[TRUNCATED]"
def redaction_canaries(
    paths: Iterable[str] = (),
    *,
    additional: Iterable[str] = (),
) -> tuple[str, ...]:
    """Derive the bounded, deterministic private values used by all producers."""

    known: set[str] = set()
    aggregate_bytes = 0

    def add(candidate: str, *, allow_short: bool) -> None:
        nonlocal aggregate_bytes
        if "\n" in candidate or "\r" in candidate:
            raise TargetError("redaction_secret_invalid", "redaction secret is invalid")
        encoded_size = len(candidate.encode("utf-8"))
        if encoded_size > MAX_REDACTION_SECRET_BYTES:
            raise TargetError("redaction_secret_invalid", "redaction secret is invalid")
        if (allow_short or encoded_size >= 4) and candidate and candidate not in known:
            if (
                len(known) >= MAX_REDACTION_SECRETS
                or aggregate_bytes + encoded_size > MAX_REDACTION_SECRET_AGGREGATE_BYTES
            ):
                raise TargetError("redaction_secret_invalid", "redaction secret is invalid")
            known.add(candidate)
            aggregate_bytes += encoded_size

    try:
        path_iterator = iter(paths)
    except TypeError:
        raise TargetError("redaction_secret_invalid", "redaction secret is invalid") from None
    supplied_paths = 0
    for path in path_iterator:
        supplied_paths += 1
        if (
            supplied_paths > MAX_REDACTION_PRIVATE_PATHS
            or not isinstance(path, str)
            or not path.isascii()
            or not path.startswith("/")
            or path == "/"
            or path.endswith("/")
            or "//" in path
            or "\x00" in path
        ):
            raise TargetError("redaction_secret_invalid", "redaction secret is invalid")
        components = path.split("/")[1:]
        if (
            len(components) > _MAX_REMOTE_PATH_DEPTH
            or any(component in {"", ".", ".."} for component in components)
        ):
            raise TargetError("redaction_secret_invalid", "redaction secret is invalid")
        add(path, allow_short=True)
        add(components[-1], allow_short=True)
        for depth in range(len(components) - 1, 1, -1):
            add("/" + "/".join(components[:depth]), allow_short=True)

    try:
        additional_iterator = iter(additional)
    except TypeError:
        raise TargetError("redaction_secret_invalid", "redaction secret is invalid") from None
    supplied_additional = 0
    for candidate in additional_iterator:
        supplied_additional += 1
        if (
            supplied_additional > MAX_REDACTION_ADDITIONAL_SECRETS
            or not isinstance(candidate, str)
        ):
            raise TargetError("redaction_secret_invalid", "redaction secret is invalid")
        add(candidate, allow_short=False)

    return tuple(sorted(known, key=lambda value: (-len(value), value)))


class StreamingRedactor:
    """Redact output as bounded, independently safe line records.

    ``feed`` accepts ``str`` or UTF-8 ``bytes`` (invalid byte sequences are
    replaced).  It retains an incomplete record and emits only records ending
    in LF; CRLF is normalized to LF.  A record that exceeds ``max_pending`` is
    represented by one marker and ignored through its terminating LF.
    """

    __slots__ = (
        "_buffer",
        "_decoder",
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

        known: set[str] = set()
        aggregate_bytes = 0
        supplied = 0
        try:
            iterator = iter(secrets)
        except TypeError:
            raise TargetError("redaction_secret_invalid", "redaction secret is invalid") from None
        for secret in iterator:
            supplied += 1
            if supplied > MAX_REDACTION_SECRETS:
                raise TargetError("redaction_secret_invalid", "redaction secret is invalid")
            if isinstance(secret, bytes):
                item = secret.decode("utf-8", "replace")
            elif isinstance(secret, str):
                item = secret
            else:
                raise TargetError("redaction_secret_invalid", "redaction secret is invalid")
            if "\n" in item or "\r" in item:
                raise TargetError("redaction_secret_invalid", "redaction secret is invalid")
            encoded_size = len(item.encode("utf-8"))
            if encoded_size > MAX_REDACTION_SECRET_BYTES:
                raise TargetError("redaction_secret_invalid", "redaction secret is invalid")
            if item and item not in known:
                aggregate_bytes += encoded_size
                if aggregate_bytes > MAX_REDACTION_SECRET_AGGREGATE_BYTES:
                    raise TargetError("redaction_secret_invalid", "redaction secret is invalid")
                known.add(item)
        known_secrets = tuple(sorted(known, key=lambda secret: (-len(secret), secret)))
        self._secret_re = (
            re.compile("|".join(re.escape(secret) for secret in known_secrets)) if known_secrets else None
        )
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
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

    def _decode(self, chunk: str | bytes) -> str:
        if isinstance(chunk, bytes):
            return self._decoder.decode(chunk, final=False)
        if isinstance(chunk, str):
            pending = self._decoder.decode(b"", final=True)
            self._decoder.reset()
            return pending + chunk
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
        text = _CONTROL_RE.sub("", text)
        if self._secret_re is not None:
            text = self._secret_re.sub(_REDACTED, text)
        text = _URL_USERINFO_RE.sub(r"\1[REDACTED]@", text)
        text = _CREDENTIAL_RE.sub(_REDACTED, text)
        text = _BEARER_RE.sub(_REDACTED, text)
        text = _TOKEN_SIGNATURE_RE.sub(_REDACTED, text)
        text = _HOME_RE.sub(_REDACTED_HOME, text)
        text = _IPV6_RE.sub(_REDACTED_ADDRESS, text)
        return _IPV4_RE.sub(_REDACTED_ADDRESS, text)

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
        return self._feed_text(self._decode(chunk))

    def _feed_text(self, text: str) -> str:
        """Consume decoded text while retaining one bounded incomplete record."""
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
        decoder_tail = self._decoder.decode(b"", final=True)
        self._decoder.reset()
        prefix = self._feed_text(decoder_tail)
        self._finalized = True
        if self._discarding:
            self._buffer = ""
            self._discarding = False
            self._pending_cr = False
            return prefix
        # A trailing CR cannot form a CRLF once finalization starts.  It is an
        # unsafe control character and will not be visible, so retaining it is
        # unnecessary and would needlessly consume pending-line capacity.
        self._pending_cr = False
        result = self._emit_line(self._buffer, terminated=False)
        self._buffer = ""
        return prefix + result


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
import codecs as _targetctl_codecs, re as _targetctl_re
_targetctl_ansi=_targetctl_re.compile(r'(?:\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|\x1b[PX^_][\s\S]*?\x1b\\|\x1b[^\[\]PX^_])')
_targetctl_unterminated=_targetctl_re.compile(r'\x1b(?:\][\s\S]*|\[[\s\S]*|[PX^_][\s\S]*|[\s\S]?)$')
_targetctl_url=_targetctl_re.compile(r'\b([A-Za-z][A-Za-z0-9+.-]*://)[^/?#\s@]+@')
_targetctl_bearer=_targetctl_re.compile(r'(?i)\bbearer[ \t]+[^\s,;]+')
_targetctl_credential=_targetctl_re.compile(r'(?i)\b(?:api_key|api-key|access_token|refresh_token|token|secret|password|passwd|authorization|bearer)\s*(?:=|:)\s*(?:bearer\s+)?[^\s,;]+')
_targetctl_token=_targetctl_re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9_]{8,}|sk-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b')
_targetctl_ipv6=_targetctl_re.compile(r'(?i)(?<![0-9a-f:])(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:[0-9a-f]{1,4}|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?)(?![0-9a-f:])')
_targetctl_ipv4=_targetctl_re.compile(r'(?<![0-9.])(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(?![0-9.])')
_targetctl_home=_targetctl_re.compile(r'(?:(?:/home|/Users)/[A-Za-z0-9._-]+(?:/[^\s\x00-\x1f\x7f]*)*|~[A-Za-z0-9._-]*(?:/[^\s\x00-\x1f\x7f]*)*)')
_targetctl_path_bytes=4096
_targetctl_path_depth=32
_targetctl_path_count=2
_targetctl_additional_count=3
_targetctl_secret_bytes=_targetctl_path_bytes
_targetctl_secret_count=_targetctl_path_count*_targetctl_path_depth+_targetctl_additional_count
_targetctl_secret_aggregate=_targetctl_secret_count*_targetctl_secret_bytes
def _targetctl_redaction_canaries(paths=(),additional=()):
    values=set(); aggregate=0; supplied=0
    def add(candidate,allow_short):
        nonlocal aggregate
        if '\n' in candidate or '\r' in candidate: raise ValueError('invalid redaction secrets')
        size=len(candidate.encode('utf-8'))
        if size>_targetctl_secret_bytes: raise ValueError('invalid redaction secrets')
        if candidate and (allow_short or size>=4) and candidate not in values:
            if len(values)>=_targetctl_secret_count or aggregate+size>_targetctl_secret_aggregate: raise ValueError('invalid redaction secrets')
            values.add(candidate); aggregate+=size
    for item in paths:
        supplied+=1
        if supplied>_targetctl_path_count or not isinstance(item,str) or not item.isascii() or not item.startswith('/') or item=='/' or item.endswith('/') or '//' in item or '\x00' in item: raise ValueError('invalid redaction secrets')
        components=item.split('/')[1:]
        if len(components)>_targetctl_path_depth or any(component in ('','.','..') for component in components): raise ValueError('invalid redaction secrets')
        add(item,True); add(components[-1],True)
        for depth in range(len(components)-1,1,-1): add('/'+'/'.join(components[:depth]),True)
    supplied=0
    for item in additional:
        supplied+=1
        if supplied>_targetctl_additional_count or not isinstance(item,str): raise ValueError('invalid redaction secrets')
        add(item,False)
    return tuple(sorted(values,key=lambda value:(-len(value),value)))
def _targetctl_redactor(secrets):
    values=set(); supplied=0; aggregate=0
    for item in secrets:
        supplied+=1
        if supplied>_targetctl_secret_count or not isinstance(item,str) or '\n' in item or '\r' in item: raise ValueError('invalid redaction secrets')
        size=len(item.encode('utf-8'))
        if size>_targetctl_secret_bytes: raise ValueError('invalid redaction secrets')
        if item and item not in values:
            if aggregate+size>_targetctl_secret_aggregate: raise ValueError('invalid redaction secrets')
            values.add(item); aggregate+=size
    return {'secrets':tuple(sorted(values,key=lambda value:(-len(value),value))),'buffer':'','discard':False,'out':bytearray(),'full':False,'decoder':_targetctl_codecs.getincrementaldecoder('utf-8')('replace')}
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
    text=''.join(character for character in text if not (ord(character)<32 or 127<=ord(character)<160))
    for secret in state['secrets']: text=text.replace(secret,'[REDACTED]')
    text=_targetctl_url.sub(r'\1[REDACTED]@',text)
    text=_targetctl_credential.sub('[REDACTED]',text)
    text=_targetctl_bearer.sub('[REDACTED]',text)
    text=_targetctl_token.sub('[REDACTED]',text)
    text=_targetctl_home.sub('[REDACTED_HOME]',text)
    text=_targetctl_ipv6.sub('[REDACTED_ADDRESS]',text)
    return _targetctl_ipv4.sub('[REDACTED_ADDRESS]',text)
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
