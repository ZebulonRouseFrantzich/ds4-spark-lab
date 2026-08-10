"""Explicit one-time removal of an exact retired lifecycle state."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

from .common import TargetError
from .source import _load_capabilities
from .transport import SSHTransport, select_transport
from .workflow import load_operational_target

MIGRATION_OPERATION = "migrate-state"
_MIGRATION_LEASE_SECONDS = 120
_MIGRATION_ERRORS = frozenset(
    {
        "migration_entries_invalid",
        "migration_state_invalid",
        "migration_target_live",
    }
)
_MIGRATION_STATUSES = frozenset({"migrated", "current", "not_found"})


def _fail(code: str, message: str = "target state migration is unavailable") -> None:
    raise TargetError(code, message)


# This source executes after remote.py in the isolated helper namespace. It uses
# the helper's dirfd, marker, lock, JSON, and bounded-state primitives rather
# than introducing another remote execution path.
MIGRATION_EXTENSION = r'''
import fcntl

_MIGRATION_MAX_STATE = 65536
_MIGRATION_MAX_LOG = 1048576
_MIGRATION_FILES = frozenset({
  'run.json', 'launch.json', 'supervisor.py', 'server.log', 'ack.json',
  '.targetctl-lifecycle-v1.lock',
})
_MIGRATION_TEMP_PREFIXES = (
  '.run.json.', '.launch.json.', '.supervisor.py.', '.server.log.',
  '.ack.json.', '.targetctl-lifecycle-',
)
_MIGRATION_LEGACY_PROFILE = {
  'schema_version': 1,
  'accelerator': 'cuda',
  'context_tokens': 32768,
  'bind': 'loopback',
  'continuation_mtp_mode': 2,
  'dspark_enabled': True,
  'drafter_enabled': True,
}


def _migration_signature(item):
  return (
    item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
    item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
  )


def _migration_duplicate_free(pairs):
  value = {}
  for key, item in pairs:
    if key in value:
      raise ValueError('duplicate key')
    value[key] = item
  return value


def _migration_read_pinned(fd, maximum):
  try:
    before = os.fstat(fd)
    os.lseek(fd, 0, os.SEEK_SET)
    raw = os.read(fd, maximum + 1)
    if len(raw) > maximum or os.read(fd, 1):
      _fail('migration_entries_invalid')
    after = os.fstat(fd)
  except OSError:
    _fail('migration_entries_invalid')
  if _migration_signature(before) != _migration_signature(after):
    _fail('migration_entries_invalid')
  return raw


def _migration_open_run(root_fd):
  try:
    named_before = os.stat('run.json', dir_fd=root_fd, follow_symlinks=False)
  except FileNotFoundError:
    return None
  except OSError:
    _fail('migration_entries_invalid')
  if (
    not stat.S_ISREG(named_before.st_mode)
    or named_before.st_uid != os.geteuid()
    or stat.S_IMODE(named_before.st_mode) != 0o600
    or named_before.st_nlink != 1
  ):
    _fail('migration_entries_invalid')
  try:
    fd, item = _open_regular(
      'run.json', dir_fd=root_fd, flags=os.O_RDONLY | os.O_NONBLOCK,
    )
  except HelperError:
    _fail('migration_entries_invalid')
  try:
    raw = _migration_read_pinned(fd, _MIGRATION_MAX_STATE)
    named = os.stat('run.json', dir_fd=root_fd, follow_symlinks=False)
    if _migration_signature(item) != _migration_signature(named):
      _fail('migration_entries_invalid')
    state = json.loads(raw.decode('ascii'), object_pairs_hook=_migration_duplicate_free)
  except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
    os.close(fd)
    _fail('migration_state_invalid')
  return {'fd': fd, 'signature': _migration_signature(item), 'raw': raw, 'state': state}


def _migration_current(state):
  return (
    type(state) is dict
    and type(state.get('schema_version')) is int
    and _valid_run_state(state)
    and type(state.get('launch_profile')) is dict
    and state['launch_profile'].get('schema_version') == 2
  )


def _migration_legacy(state):
  if (
    type(state) is not dict
    or set(state) != RUN_STATE_FIELDS
    or type(state.get('schema_version')) is not int
    or state.get('schema_version') != RUN_STATE_SCHEMA_VERSION
    or state.get('state') != 'stopped'
    or state.get('cleanup_complete') is not True
    or type(state.get('launch_profile')) is not dict
    or state['launch_profile'] != _MIGRATION_LEGACY_PROFILE
  ):
    return False
  profile = state['launch_profile']
  if (
    type(profile['schema_version']) is not int
    or type(profile['accelerator']) is not str
    or type(profile['context_tokens']) is not int
    or type(profile['bind']) is not str
    or type(profile['continuation_mtp_mode']) is not int
    or type(profile['dspark_enabled']) is not bool
    or type(profile['drafter_enabled']) is not bool
  ):
    return False
  candidate = dict(state)
  candidate['launch_profile'] = LAUNCH_PROFILE
  if not _valid_run_state(candidate, terminal=True):
    return False
  cleanup = state['cleanup']
  return (
    type(cleanup) is dict
    and set(cleanup) == {'process', 'socket', 'lock', 'temp', 'server_log_sha256'}
    and all(cleanup[key] in {'cleared', 'not_found'} for key in ('process', 'socket', 'lock', 'temp'))
  )


def _migration_scan(root_fd):
  present = set()
  extra = False
  count = 0
  try:
    iterator = os.scandir(root_fd)
    try:
      for entry in iterator:
        count += 1
        if count > MAX_ENTRIES:
          _fail('migration_entries_invalid')
        name = entry.name
        if name in _MIGRATION_FILES:
          present.add(name)
        elif any(name.startswith(prefix) for prefix in _MIGRATION_TEMP_PREFIXES):
          extra = True
    finally:
      iterator.close()
  except HelperError:
    raise
  except OSError:
    _fail('migration_entries_invalid')
  if extra:
    _fail('migration_entries_invalid')
  return present


def _migration_open_entries(root_fd, run_record, present):
  records = {'run.json': run_record}
  guard_fd = None
  try:
    for name in sorted(present - {'run.json'}):
      try:
        fd, item = _open_regular(
          name,
          dir_fd=root_fd,
          flags=(
            os.O_RDWR | os.O_NONBLOCK
            if name == '.targetctl-lifecycle-v1.lock'
            else os.O_RDONLY | os.O_NONBLOCK
          ),
        )
      except HelperError:
        _fail('migration_entries_invalid')
      records[name] = {
        'fd': fd,
        'signature': _migration_signature(item),
      }
      if name == '.targetctl-lifecycle-v1.lock':
        guard_fd = fd
        try:
          fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
          _fail('migration_target_live')
        except OSError:
          _fail('migration_entries_invalid')
    return records, guard_fd
  except BaseException:
    for record in records.values():
      if record is not None:
        try:
          os.close(record['fd'])
        except OSError:
          pass
    raise


def _migration_assert_record(root_fd, name, record):
  try:
    descriptor = os.fstat(record['fd'])
    named = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
  except OSError:
    _fail('migration_entries_invalid')
  if (
    _migration_signature(descriptor) != record['signature']
    or _migration_signature(named) != record['signature']
  ):
    _fail('migration_entries_invalid')


def _migration_assert_entries(root_fd, records, remaining):
  if _migration_scan(root_fd) != remaining:
    _fail('migration_entries_invalid')
  for name, record in records.items():
    try:
      descriptor = os.fstat(record['fd'])
    except OSError:
      _fail('migration_entries_invalid')
    observed = _migration_signature(descriptor)
    if name in remaining:
      if observed != record['signature']:
        _fail('migration_entries_invalid')
      _migration_assert_record(root_fd, name, record)
    else:
      expected = record['signature']
      if (
        observed[:5] != expected[:5]
        or descriptor.st_nlink != 0
        or observed[6:8] != expected[6:8]
      ):
        _fail('migration_entries_invalid')
      try:
        os.stat(name, dir_fd=root_fd, follow_symlinks=False)
      except FileNotFoundError:
        continue
      except OSError:
        _fail('migration_entries_invalid')
      _fail('migration_entries_invalid')
  run_record = records.get('run.json')
  if run_record is not None and 'run.json' in remaining:
    if not hmac.compare_digest(
      _migration_read_pinned(run_record['fd'], _MIGRATION_MAX_STATE),
      run_record['raw'],
    ):
      _fail('migration_state_invalid')


def _migration_validate_log(records, state):
  expected = state['cleanup']['server_log_sha256']
  record = records.get('server.log')
  if record is None:
    return
  if not _is_hex_digest(expected):
    _fail('migration_state_invalid')
  raw = _migration_read_pinned(record['fd'], _MIGRATION_MAX_LOG)
  if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected):
    _fail('migration_state_invalid')


def _migration_pid_present(pid):
  if pid is None:
    return False
  flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0)
  try:
    fd = os.open('/proc/%d' % pid, flags)
  except FileNotFoundError:
    return False
  except OSError:
    _fail('migration_target_live')
  try:
    item = os.fstat(fd)
    if not stat.S_ISDIR(item.st_mode):
      _fail('migration_target_live')
    return True
  finally:
    os.close(fd)


def _migration_group_present(pgid):
  if pgid is None:
    return False
  try:
    os.killpg(pgid, 0)
    return True
  except ProcessLookupError:
    return False
  except OSError:
    _fail('migration_target_live')


def _migration_listener_present(port):
  wanted = '%04X' % port
  for path in ('/proc/net/tcp', '/proc/net/tcp6'):
    try:
      with open(path, encoding='ascii') as handle:
        body = handle.read(1048577)
    except (OSError, UnicodeError):
      _fail('migration_target_live')
    if len(body) > 1048576:
      _fail('migration_target_live')
    for line in body.splitlines()[1:]:
      fields = line.split()
      try:
        number = fields[1].rsplit(':', 1)[1]
      except (IndexError, ValueError):
        _fail('migration_target_live')
      if (
        len(fields) > 9
        and fields[3] == '0A'
        and number == wanted
        and fields[7] == str(os.geteuid())
      ):
        return True
  return False


def _migration_assert_quiescent(state):
  if (
    _migration_pid_present(state['supervisor_pid'])
    or _migration_pid_present(state['child_pid'])
    or _migration_group_present(state['supervisor_pid'])
    or _migration_group_present(state['child_pgid'])
    or _migration_listener_present(state['port'])
  ):
    _fail('migration_target_live')


def _migration_acquire_lease(root_fd, root_identity, run_token, lease_seconds):
  lease_seconds = _lease_seconds(lease_seconds)
  _assert_pinned_root(root_fd, root_identity)
  _read_marker(root_fd, 'run', run_token)
  state = {
    'boot_id': _boot_id(),
    'deadline_monotonic_ns': time.monotonic_ns() + lease_seconds * 1000000000,
    'token': secrets.token_hex(32),
  }
  if not _install_lock(root_fd, state):
    _fail('lock_busy')
  try:
    fd, item = _open_regular(LOCK_NAME, dir_fd=root_fd, flags=os.O_RDONLY | os.O_NONBLOCK)
    observed = _lock_state(fd)
    if observed != state:
      os.close(fd)
      _fail('unsafe_lock')
    _assert_named_identity(root_fd, LOCK_NAME, _identity(fd), 'unsafe_lock')
    _assert_pinned_root(root_fd, root_identity)
    _read_marker(root_fd, 'run', run_token)
    return {
      'fd': fd,
      'identity': _identity(fd),
      'signature': _migration_signature(item),
      'state': state,
    }
  except BaseException:
    try:
      lock_fd, _ = _open_regular(LOCK_NAME, dir_fd=root_fd, flags=os.O_RDONLY | os.O_NONBLOCK)
      try:
        lock_state = _lock_state(lock_fd)
        if hmac.compare_digest(lock_state.get('token', ''), state['token']):
          _remove_lock(root_fd, lock_fd, _identity(lock_fd))
      finally:
        os.close(lock_fd)
    except BaseException:
      pass
    raise


def _migration_assert_lease(root_fd, root_identity, run_token, lease):
  _assert_pinned_root(root_fd, root_identity)
  _read_marker(root_fd, 'run', run_token)
  try:
    item = os.fstat(lease['fd'])
  except OSError:
    _fail('unsafe_lock')
  if _migration_signature(item) != lease['signature']:
    _fail('unsafe_lock')
  _assert_named_identity(root_fd, LOCK_NAME, lease['identity'], 'unsafe_lock')
  observed = _lock_state(lease['fd'])
  if (
    observed != lease['state']
    or not hmac.compare_digest(observed['token'], lease['state']['token'])
    or not hmac.compare_digest(observed['boot_id'], _boot_id())
    or time.monotonic_ns() >= observed['deadline_monotonic_ns']
  ):
    _fail('unsafe_lock')


def _migration_release_lease(root_fd, root_identity, run_token, lease):
  _assert_pinned_root(root_fd, root_identity)
  _read_marker(root_fd, 'run', run_token)
  try:
    item = os.fstat(lease['fd'])
  except OSError:
    _fail('unsafe_lock')
  if _migration_signature(item) != lease['signature']:
    _fail('unsafe_lock')
  _assert_named_identity(root_fd, LOCK_NAME, lease['identity'], 'unsafe_lock')
  state = _lock_state(lease['fd'])
  if not hmac.compare_digest(state.get('token', ''), lease['state']['token']):
    _fail('lock_token_mismatch')
  _remove_lock(root_fd, lease['fd'], lease['identity'])
  _assert_pinned_root(root_fd, root_identity)
  _read_marker(root_fd, 'run', run_token)


def _migration_before_mutation(root_fd, root_identity, run_token, lease, records, remaining, state):
  _migration_assert_lease(root_fd, root_identity, run_token, lease)
  _migration_assert_entries(root_fd, records, remaining)
  _migration_assert_quiescent(state)


@register_action('migrate_state')
def migrate_state(payload):
  data = _require_object(payload, {'run_dir', 'run_token', 'lease_seconds'})
  run_dir = _validate_absolute_path(data['run_dir'])
  run_token = data['run_token']
  lease_seconds = _lease_seconds(data['lease_seconds'])
  root_fd = _open_root(run_dir)
  root_identity = None
  run_record = None
  records = {}
  guard_fd = None
  lease = None
  primary = None
  try:
    root_identity = _root_identity(root_fd, 'run', run_token)
    run_record = _migration_open_run(root_fd)
    present = _migration_scan(root_fd)
    if run_record is None:
      if present:
        _fail('migration_entries_invalid')
      lease = _migration_acquire_lease(root_fd, root_identity, run_token, lease_seconds)
      _migration_assert_lease(root_fd, root_identity, run_token, lease)
      observed = _migration_open_run(root_fd)
      if observed is not None:
        os.close(observed['fd'])
        _fail('migration_entries_invalid')
      if _migration_scan(root_fd):
        _fail('migration_entries_invalid')
      return {'status': 'not_found'}
    state = run_record['state']
    if _migration_current(state):
      return {'status': 'current'}
    if not _migration_legacy(state):
      _fail('migration_state_invalid')
    records, guard_fd = _migration_open_entries(root_fd, run_record, present)
    run_record = None
    _migration_validate_log(records, state)
    _migration_assert_entries(root_fd, records, set(present))
    _migration_assert_quiescent(state)
    lease = _migration_acquire_lease(root_fd, root_identity, run_token, lease_seconds)
    remaining = set(present)
    _migration_before_mutation(root_fd, root_identity, run_token, lease, records, remaining, state)
    for name in ('launch.json', 'supervisor.py', 'server.log', 'ack.json', '.targetctl-lifecycle-v1.lock', 'run.json'):
      if name not in remaining:
        continue
      _migration_before_mutation(root_fd, root_identity, run_token, lease, records, remaining, state)
      try:
        os.unlink(name, dir_fd=root_fd)
      except OSError:
        _fail('migration_entries_invalid')
      remaining.remove(name)
    _migration_assert_lease(root_fd, root_identity, run_token, lease)
    _migration_assert_entries(root_fd, records, remaining)
    try:
      os.fsync(root_fd)
    except OSError:
      _fail('migration_entries_invalid')
    return {'status': 'migrated'}
  except BaseException as error:
    primary = error
    raise
  finally:
    if run_record is not None:
      try:
        os.close(run_record['fd'])
      except OSError:
        pass
    for record in records.values():
      try:
        os.close(record['fd'])
      except OSError:
        pass
    if lease is not None:
      try:
        _migration_release_lease(root_fd, root_identity, run_token, lease)
      except BaseException:
        if primary is None:
          raise
      finally:
        try:
          os.close(lease['fd'])
        except OSError:
          pass
    os.close(root_fd)
'''


def migrate_state(
    repo_root: str | os.PathLike[str],
    target: str,
    *,
    transport: SSHTransport | None = None,
) -> str:
    """Run the one bounded target-side migration and validate its exact result."""

    config = load_operational_target(repo_root, target)
    config.validate_for(MIGRATION_OPERATION)
    if config.mode != "ssh":
        _fail("migration_local_unsupported", "target state migration requires an SSH target")
    capabilities = _load_capabilities(Path(config.source_root), config.name)
    if capabilities is None:
        _fail("migration_capability_missing", "target migration capability is unavailable")
    selected = transport if transport is not None else select_transport(config, repo_root=Path(config.source_root))
    if not isinstance(selected, SSHTransport) and transport is None:
        _fail("migration_transport_invalid", "target state migration requires an SSH target")
    value = selected.run_helper(
        "migrate_state",
        {
            "run_dir": config.run_dir,
            "run_token": capabilities["run_token"],
            "lease_seconds": _MIGRATION_LEASE_SECONDS,
        },
        extension_source=MIGRATION_EXTENSION,
        allowed_error_codes=_MIGRATION_ERRORS,
        timeout=60.0,
    )
    if (
        not isinstance(value, Mapping)
        or set(value) != {"status"}
        or not isinstance(value["status"], str)
        or value["status"] not in _MIGRATION_STATUSES
    ):
        _fail("migration_response_invalid", "target state migration returned invalid evidence")
    return value["status"]


def execute_migration(repo_root: str | os.PathLike[str], target: str) -> dict[str, Any]:
    """Execute the dedicated migration without entering the normal workflow."""

    return {"status": "succeeded", "outcome": migrate_state(repo_root, target)}


def structured_migration_result(repo_root: str | os.PathLike[str], target: str) -> dict[str, Any]:
    """Return only fixed-cardinality, private-safe CLI fields."""

    try:
        return {
            "schema": 1,
            "operation": MIGRATION_OPERATION,
            "target": target,
            **execute_migration(repo_root, target),
        }
    except KeyboardInterrupt:
        return {
            "schema": 1,
            "operation": MIGRATION_OPERATION,
            "target": target,
            "status": "failed",
            "error": "interrupted",
        }
    except TargetError as error:
        return {
            "schema": 1,
            "operation": MIGRATION_OPERATION,
            "target": target,
            "status": "failed",
            "error": error.code,
        }
    except Exception:
        return {
            "schema": 1,
            "operation": MIGRATION_OPERATION,
            "target": target,
            "status": "failed",
            "error": "internal_error",
        }
