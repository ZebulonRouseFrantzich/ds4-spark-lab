from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest

from scripts.targetctl.common import (
    TargetError,
    canonical_json_bytes,
    length_frame,
    read_json_file,
    record_id_for,
    sha256_framed,
    write_json_atomic,
)
from scripts.targetctl.config import load_target
from scripts.targetctl.redaction import (
    MAX_REDACTION_SECRET_AGGREGATE_BYTES,
    MAX_REDACTION_SECRETS,
    StreamingRedactor,
    redact_text,
    redaction_canaries,
)


class TargetConfigTests(unittest.TestCase):
    def _config(self, root: Path, body: str) -> Path:
        path = root / "targets.toml"
        path.write_text(body, encoding="utf-8")
        return path

    def _ssh_body(self, **paths: str) -> str:
        values = {
            "workdir": "/mnt/ds4-data/spark/work",
            "run_dir": "/mnt/ds4-data/spark/run",
            "model_path": "/mnt/ds4-models/primary/release",
            "drafter_path": "/mnt/ds4-models/drafter/release",
        }
        values.update(paths)
        return """schema_version = 1
[spark]
name = "spark"
mode = "ssh"
ssh_host = "alias"
workdir = "{workdir}"
run_dir = "{run_dir}"
api_base_url = "http://127.0.0.1:8080"
model_path = "{model_path}"
drafter_path = "{drafter_path}"
""".format(**values)

    def _assert_value_free(self, action, secret: str) -> None:
        with self.assertRaises(TargetError) as raised:
            action()
        self.assertNotIn(secret, str(raised.exception))
        self.assertNotIn(secret, repr(raised.exception))

    def test_minimal_local_target_uses_xdg_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self._config(root, 'schema_version = 1\n[local]\nname = "local"\nmode = "local"\n')
            old_state = os.environ.get("XDG_STATE_HOME")
            try:
                os.environ["XDG_STATE_HOME"] = str(root / "state")
                target = load_target(root, "local", config)
            finally:
                if old_state is None:
                    os.environ.pop("XDG_STATE_HOME", None)
                else:
                    os.environ["XDG_STATE_HOME"] = old_state
            self.assertEqual(target.name, "local")
            self.assertEqual(target.mode, "local")
            self.assertEqual(target.source_root, root.resolve())
            self.assertEqual(target.local_run_dir, root / "state" / "ds4-spark-lab" / "targetctl" / "local")
            target.validate_for("doctor")

    def test_private_ssh_values_are_fields_but_never_repr(self) -> None:
        secret = "private-model-value"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self._config(
                root,
                """schema_version = 1
[spark]
name = "spark"
mode = "ssh"
ssh_host = "lab_alias"
workdir = "/mnt/ds4-data/spark/work"
run_dir = "/mnt/ds4-data/spark/run"
api_base_url = "http://127.0.0.1:8080"
model_path = "/mnt/ds4-models/private-model-value/main"
drafter_path = "/mnt/ds4-models/drafter/main"
""",
            )
            target = load_target(root, "spark", config)
            self.assertEqual(target.model_path, f"/mnt/ds4-models/{secret}/main")
            self.assertNotIn(secret, repr(target))
            self.assertNotIn("lab_alias", repr(target))
            target.validate_for("smoke")

    def test_config_rejects_missing_unknown_placeholder_and_unsafe_values_without_values(self) -> None:
        secret = "do-not-print-this"
        cases = (
            """schema_version = 1
[spark]
name = "spark"
mode = "ssh"
ssh_host = "alias"
workdir = "/mnt/ds4-data/spark/work"
run_dir = "/mnt/ds4-data/spark/run"
api_base_url = "http://127.0.0.1:8080"
model_path = "/mnt/ds4-models/primary/release"
""",
            """schema_version = 1
[local]
name = "local"
mode = "local"
unknown = "do-not-print-this"
""",
            """schema_version = 1
[spark]
name = "spark"
mode = "ssh"
ssh_host = "<logical-ssh-alias>"
workdir = "/mnt/ds4-data/spark/work"
run_dir = "/mnt/ds4-data/spark/run"
api_base_url = "http://127.0.0.1:8080"
model_path = "/mnt/ds4-models/primary/release"
drafter_path = "/mnt/ds4-models/drafter/release"
""",
            """schema_version = 1
[spark]
name = "spark"
mode = "ssh"
ssh_host = "alias"
workdir = "/mnt/ds4-data/spark/work/../do-not-print-this"
run_dir = "/mnt/ds4-data/spark/run"
api_base_url = "http://user:do-not-print-this@127.0.0.1:8080"
model_path = "/mnt/ds4-models/primary/release"
drafter_path = "/mnt/ds4-models/drafter/release"
""",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for body in cases:
                config = self._config(root, body)
                self._assert_value_free(lambda: load_target(root, "spark" if "[spark]" in body else "local", config), secret)

    def test_lexical_path_overlap_is_rejected_for_every_remote_root(self) -> None:
        secret = "nested-private-path"
        root_path = "/mnt/ds4-data/spark/shared"
        fields = ("workdir", "run_dir", "model_path", "drafter_path")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, first in enumerate(fields):
                for second in fields[index + 1 :]:
                    with self.subTest(first=first, second=second):
                        config = self._config(
                            root,
                            self._ssh_body(
                                **{
                                    first: root_path,
                                    second: f"{root_path}/{secret}",
                                }
                            ),
                        )
                        self._assert_value_free(
                            lambda config=config: load_target(root, "spark", config),
                            secret,
                        )

    def test_dedicated_mounted_remote_paths_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workdir = "/mnt/ds4-data/spark/work"
            run_dir = "/mnt/ds4-data/spark/run"
            model_path = "/mnt/ds4-models/primary/release"
            drafter_path = "/mnt/ds4-models/drafter/release"
            config = self._config(
                root,
                self._ssh_body(
                    workdir=workdir,
                    run_dir=run_dir,
                    model_path=model_path,
                    drafter_path=drafter_path,
                ),
            )
            target = load_target(root, "spark", config)
            self.assertEqual(
                (target.workdir, target.run_dir, target.model_path, target.drafter_path),
                (workdir, run_dir, model_path, drafter_path),
            )
            target.validate_for("doctor")

    def test_shallow_and_high_blast_radius_mutable_paths_fail_at_load(self) -> None:
        unsafe_paths = (
            "/",
            "/home",
            "/root",
            "/tmp",
            "/mnt",
            "/mnt/ds4-data",
            "/mnt/ds4-data/spark",
            "/home/controller/ds4/spark",
            "/usr/local/share/ds4",
            "/var/cache/ds4/spark",
            "/etc/ds4/spark/work",
            "/opt/ds4/spark/work",
            "/srv/ds4/spark/work",
            "/cache/ds4/spark/work",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for field_name in ("workdir", "run_dir"):
                for unsafe_path in unsafe_paths:
                    with self.subTest(field_name=field_name, unsafe_path=unsafe_path):
                        config = self._config(root, self._ssh_body(**{field_name: unsafe_path}))
                        self._assert_value_free(
                            lambda config=config: load_target(root, "spark", config),
                            unsafe_path,
                        )

    def test_user_home_artifact_paths_load_without_mutable_root_denylist(self) -> None:
        model_path = "/home/ubuntu/models/Qwen3-32B-Q4_K_M.gguf"
        drafter_path = "/home/ubuntu/models/Qwen3-0.6B-Q8_0.gguf"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self._config(
                root,
                self._ssh_body(model_path=model_path, drafter_path=drafter_path),
            )
            target = load_target(root, "spark", config)
            self.assertEqual((target.model_path, target.drafter_path), (model_path, drafter_path))
            target.validate_for("serve")


    def test_artifact_paths_reject_root_shallow_and_non_normalized_inputs(self) -> None:
        invalid_paths = (
            "/",
            "/home",
            "/home/ubuntu",
            "/home/ubuntu/models/../model.gguf",
            "/home/ubuntu//models/model.gguf",
            "/home/ubuntu/models/model.gguf/",
            "/home/ubuntu/models/\x01model.gguf",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for field_name in ("model_path", "drafter_path"):
                for invalid_path in invalid_paths:
                    with self.subTest(field_name=field_name, invalid_path=invalid_path):
                        config = self._config(root, self._ssh_body(**{field_name: invalid_path}))
                        self._assert_value_free(
                            lambda config=config: load_target(root, "spark", config),
                            invalid_path,
                        )

    def test_remote_paths_reject_traversal_and_non_normalized_separators(self) -> None:
        invalid_paths = (
            "/mnt/ds4-data/spark/work/../unsafe",
            "/mnt/ds4-data//spark/work",
            "/mnt/ds4-data/spark/work/",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for invalid_path in invalid_paths:
                with self.subTest(invalid_path=invalid_path):
                    config = self._config(root, self._ssh_body(workdir=invalid_path))
                    self._assert_value_free(
                        lambda config=config: load_target(root, "spark", config),
                        invalid_path,
                    )


class CommonTests(unittest.TestCase):
    def test_canonical_record_ids_and_length_framing_are_deterministic(self) -> None:
        left = {"b": [2, 1], "a": "value"}
        right = {"a": "value", "b": [2, 1]}
        self.assertEqual(canonical_json_bytes(left), b'{"a":"value","b":[2,1]}')
        self.assertEqual(record_id_for(left), record_id_for(right))
        self.assertNotEqual(length_frame(b"a", b"bc"), length_frame(b"ab", b"c"))
        self.assertNotEqual(sha256_framed(b"a", b"bc"), sha256_framed(b"ab", b"c"))

    def test_atomic_json_rejects_unknown_keys_and_symlink_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "record.json"
            write_json_atomic(target, {"schema": 1}, allowed_keys={"schema"}, required_keys={"schema"})
            self.assertEqual(read_json_file(target, allowed_keys={"schema"}, required_keys={"schema"}), {"schema": 1})
            with self.assertRaises(TargetError):
                write_json_atomic(target, {"schema": 1, "extra": True}, allowed_keys={"schema"})
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaises(TargetError):
                write_json_atomic(link, {"schema": 1}, allowed_keys={"schema"})
            with self.assertRaises(TargetError):
                read_json_file(link, allowed_keys={"schema"})


class RedactionTests(unittest.TestCase):
    _OVERSIZE = "[REDACTED_OVERSIZE]"

    def _stream(self, value: str, *, max_output: int | None = None) -> tuple[str, StreamingRedactor]:
        redactor = (
            StreamingRedactor()
            if max_output is None
            else StreamingRedactor(max_output=max_output)
        )
        return redactor.feed(value) + redactor.finalize(), redactor

    def _assert_redacted_at_every_cut(
        self,
        record: str,
        private_values: tuple[str, ...],
        *,
        known_secrets: tuple[str, ...] = (),
    ) -> None:
        for cut in range(len(record) + 1):
            with self.subTest(record=record, cut=cut):
                redactor = StreamingRedactor(known_secrets)
                output = (
                    redactor.feed(record[:cut])
                    + redactor.feed(record[cut:])
                    + redactor.feed("\n")
                    + redactor.finalize()
                )
                for private in private_values:
                    self.assertNotIn(private, output)
                self.assertIn("[REDACTED", output)

    def test_streaming_redaction_redacts_every_sensitive_grammar_at_every_cut(self) -> None:
        known_secret = "split-private-secret"
        cases = (
            (f"ordinary={known_secret}", (known_secret,), (known_secret,)),
            (
                "url=https://alice:private-url-password@example.test/model",
                ("alice:private-url-password", "private-url-password"),
                (),
            ),
            (
                "authorization: Bearer opaque-bearer-token",
                ("opaque-bearer-token",),
                (),
            ),
            (
                "path=/home/alice/private-key",
                ("/home/alice/private-key", "alice", "private-key"),
                (),
            ),
            (
                "path=/Users/bob/private-key",
                ("/Users/bob/private-key", "bob", "private-key"),
                (),
            ),
            (
                "path=~carol/private-key",
                ("~carol/private-key", "carol", "private-key"),
                (),
            ),
            ("ipv4=192.0.2.4", ("192.0.2.4",), ()),
            ("ipv6=2001:db8::1", ("2001:db8::1",), ()),
            ("found ghp_0123456789abcdefghijklmnopqrstuv", ("ghp_0123456789abcdefghijklmnopqrstuv",), ()),
        )
        for record, private_values, known_secrets in cases:
            with self.subTest(record=record):
                self._assert_redacted_at_every_cut(
                    record,
                    private_values,
                    known_secrets=known_secrets,
                )

        for label in (
            "api_key",
            "api-key",
            "access_token",
            "refresh_token",
            "token",
            "secret",
            "password",
            "passwd",
            "authorization",
        ):
            for separator in ("=", ":"):
                record = f"{label} \t{separator}\t credential-secret"
                with self.subTest(label=label, separator=separator):
                    self._assert_redacted_at_every_cut(record, ("credential-secret",))

    def test_streaming_redaction_removes_ansi_and_control_sequences_at_every_cut(self) -> None:
        record = "before \x1b]0:terminal-secret\x07 \x1b[31mcolored\x00 after"
        for cut in range(len(record) + 1):
            with self.subTest(cut=cut):
                redactor = StreamingRedactor()
                output = (
                    redactor.feed(record[:cut])
                    + redactor.feed(record[cut:])
                    + redactor.feed("\n")
                    + redactor.finalize()
                )
                for unsafe in ("terminal-secret", "\x1b", "\x00"):
                    self.assertNotIn(unsafe, output)
                self.assertIn("before", output)
                self.assertIn("after", output)

    def test_streaming_redaction_handles_multiple_lf_and_crlf_records_in_one_chunk(self) -> None:
        secret = "known-record-secret"
        chunk = (
            f"one token={secret}\n"
            "two url=https://alice:password@example.test/model\r\n"
            "three is safe\n"
        )
        output, _ = self._stream(chunk)
        for private in (secret, "alice:password", "password", "\r"):
            self.assertNotIn(private, output)
        self.assertIn("three is safe\n", output)
        self.assertGreaterEqual(output.count("\n"), 3)

    def test_streaming_redaction_redacts_final_unterminated_record(self) -> None:
        secret = "unterminated-private-secret"
        output, _ = self._stream(f"final token={secret}")
        self.assertNotIn(secret, output)
        self.assertIn("[REDACTED", output)

    def test_streaming_redaction_discards_overlong_sensitive_line_and_resumes_at_next_record(self) -> None:
        secret = "overlong-secret-that-must-never-appear"
        redactor = StreamingRedactor()
        first = redactor.feed("token=" + ("x" * 4_097))
        self.assertEqual(first, self._OVERSIZE)
        output = (
            first
            + redactor.feed(secret + "-suffix\nnext safe record\n")
            + redactor.finalize()
        )
        self.assertEqual(output.count(self._OVERSIZE), 1)
        for leaked in ("token=", "x" * 32, secret, "-suffix"):
            self.assertNotIn(leaked, output)
        self.assertIn("next safe record\n", output)

    def test_streaming_redaction_discards_overlong_ordinary_line_and_resumes_at_next_record(self) -> None:
        redactor = StreamingRedactor()
        ordinary_prefix = "ordinary diagnostic "
        first = redactor.feed(ordinary_prefix + ("z" * 4_097))
        self.assertEqual(first, self._OVERSIZE)
        output = (
            first
            + redactor.feed(" ordinary suffix\r\nnext ordinary record\r\n")
            + redactor.finalize()
        )
        self.assertEqual(output.count(self._OVERSIZE), 1)
        for leaked in (ordinary_prefix, "z" * 32, "ordinary suffix", "\r"):
            self.assertNotIn(leaked, output)
        self.assertIn("next ordinary record\n", output)

    def test_streaming_redaction_completes_oversize_discard_at_finalize_without_leaking(self) -> None:
        redactor = StreamingRedactor()
        private = "token=never-release"
        first = redactor.feed(private + ("x" * 4_097))
        self.assertEqual(first, self._OVERSIZE)
        output = first + redactor.finalize()
        self.assertEqual(output.count(self._OVERSIZE), 1)
        self.assertNotIn(private, output)
        self.assertNotIn("x" * 32, output)

    def test_streaming_redaction_bounds_output_across_many_huge_chunks(self) -> None:
        max_output = 64
        redactor = StreamingRedactor(max_output=max_output)
        pieces = []
        for index in range(32):
            private = f"chunk-{index}-private-secret"
            pieces.append(redactor.feed(f"token={private}" + ("x" * 4_097) + "\n"))
        pieces.append(redactor.finalize())
        output = "".join(pieces)
        self.assertLessEqual(len(output), max_output)
        self.assertNotIn("private-secret", output)
        self.assertNotIn("x" * 32, output)

    def test_path_canaries_include_every_nontrivial_ancestor_deterministically(self) -> None:
        home = "/home/alice/models/releases/model.gguf"
        non_home = "/srv/private/weights/releases/draft.gguf"
        expected = {
            home,
            "model.gguf",
            "/home/alice/models/releases",
            "/home/alice/models",
            "/home/alice",
            non_home,
            "draft.gguf",
            "/srv/private/weights/releases",
            "/srv/private/weights",
            "/srv/private",
        }
        canaries = redaction_canaries((home, non_home))
        self.assertEqual(canaries, tuple(sorted(expected, key=lambda value: (-len(value), value))))
        for generic in ("/", "/home", "/srv"):
            self.assertNotIn(generic, canaries)
        shared = redaction_canaries(
            (
                "/srv/private/models/releases/model.gguf",
                "/srv/private/drafters/releases/model.gguf",
            )
        )
        self.assertEqual(shared.count("model.gguf"), 1)
        self.assertEqual(shared.count("/srv/private"), 1)


    def test_interleaved_ansi_c0_c1_path_is_redacted_at_every_chunk_boundary(self) -> None:
        secret = "/srv/private/weights/releases/model.gguf"
        markers = ("\x1b[31m", "\x00", "\x85", "\x1b[0m")
        obfuscated = "".join(
            character + (markers[index % len(markers)] if index + 1 < len(secret) else "")
            for index, character in enumerate(secret)
        )
        record = ("path=" + obfuscated).encode("utf-8")
        canaries = redaction_canaries((secret,))
        for cut in range(len(record) + 1):
            with self.subTest(cut=cut):
                redactor = StreamingRedactor(canaries)
                output = (
                    redactor.feed(record[:cut])
                    + redactor.feed(record[cut:])
                    + redactor.feed(b"\n")
                    + redactor.finalize()
                )
                self.assertIn("[REDACTED]", output)
                for raw in (secret, "/srv/private/weights", "/srv/private"):
                    self.assertNotIn(raw, output)
                for control in ("\x1b", "\x00", "\x85"):
                    self.assertNotIn(control, output)


    def test_streaming_redaction_accepts_full_configuration_path_limit_and_bounds_secrets(self) -> None:
        components = [("d" + ("x" * 127)) for _ in range(31)]
        components.append("z" + ("y" * 95))
        secret = "/" + "/".join(components)
        self.assertEqual(len(secret.encode("utf-8")), 4096)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "targets.toml"
            config.write_text(
                """schema_version = 1
[spark]
name = "spark"
mode = "ssh"
ssh_host = "target-alias"
workdir = "/mnt/ds4-data/spark/work"
run_dir = "/mnt/ds4-data/spark/run"
api_base_url = "http://127.0.0.1:8080"
model_path = "/mnt/ds4-models/primary/release"
drafter_path = "%s"
""" % secret,
                encoding="utf-8",
            )
            target = load_target(root, "spark", config)
            target.validate_for("logs")
            configured_secret = target.drafter_path or ""
        self.assertEqual(configured_secret, secret)

        redactor = StreamingRedactor([configured_secret])
        output = (
            redactor.feed(configured_secret[:1023])
            + redactor.feed(configured_secret[1023:3071])
            + redactor.feed(configured_secret[3071:] + "\n")
            + redactor.finalize()
        )
        self.assertEqual(output, "[REDACTED]\n")
        second_secret = "/" + "/".join("e" + component[1:] for component in components)
        max_depth_canaries = redaction_canaries((secret, second_secret))
        self.assertEqual(len(max_depth_canaries), 64)
        self.assertLessEqual(
            sum(len(value.encode("utf-8")) for value in max_depth_canaries),
            MAX_REDACTION_SECRET_AGGREGATE_BYTES,
        )
        StreamingRedactor(max_depth_canaries)


        with self.assertRaises(TargetError) as oversized:
            StreamingRedactor([secret + "x"])
        self.assertEqual(oversized.exception.code, "redaction_secret_invalid")
        with self.assertRaises(TargetError) as excessive:
            StreamingRedactor([f"private-{index}" for index in range(MAX_REDACTION_SECRETS + 1)])
        self.assertEqual(excessive.exception.code, "redaction_secret_invalid")

    def test_one_shot_redaction_is_bounded(self) -> None:
        output = redact_text("x" * 100, max_output=16)
        self.assertLessEqual(len(output), 16)
        self.assertIn("TRUNCATED", output)
