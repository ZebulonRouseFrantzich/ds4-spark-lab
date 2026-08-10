from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
PROMPT_ROOT = REPO_ROOT / "benchmarks" / "prompts"
EXPECTED_TOKEN_COUNTS = {
    "mixed_short": 1_056,
    "mixed_medium": 26_145,
    "repo_like_small": 26_177,
    "repo_like_medium": 36_825,
    "repo_like_large": 84_349,
    "repo_like_very_large": 190_405,
    "cold_mixed_repo_like_long": 168_444,
}


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode(
        "utf-8"
    )


class PromptGenerationTests(unittest.TestCase):
    def test_manifest_freezes_exact_measured_counts_and_provenance(self) -> None:
        manifest_bytes = (PROMPT_ROOT / "manifest.json").read_bytes()
        manifest: dict[str, Any] = json.loads(manifest_bytes)
        self.assertEqual(manifest_bytes, _canonical_json(manifest))
        self.assertEqual(manifest["version"], 1)

        prompts = manifest["prompts"]
        self.assertEqual(
            {prompt["id"]: prompt["token_count"] for prompt in prompts},
            EXPECTED_TOKEN_COUNTS,
        )
        self.assertEqual({prompt["status"] for prompt in prompts}, {"measured"})

        provenance = json.loads((PROMPT_ROOT / "provenance.json").read_bytes())
        provenance_by_id = {record["id"]: record for record in provenance["artifacts"]}
        self.assertEqual(set(provenance_by_id), set(EXPECTED_TOKEN_COUNTS))
        for prompt in prompts:
            record = provenance_by_id[prompt["id"]]
            self.assertEqual(prompt["license"], record["license"])
            self.assertEqual(prompt["path"], record["path"])
            self.assertEqual(prompt["sha256"], record["sha256"])

    def test_write_regeneration_is_byte_for_byte_deterministic(self) -> None:
        manifest = json.loads((PROMPT_ROOT / "manifest.json").read_bytes())
        relative_paths = ["LICENSE.txt", "manifest.json", "provenance.json"]
        relative_paths.extend(
            str(Path(prompt["path"]).relative_to("benchmarks/prompts"))
            for prompt in manifest["prompts"]
        )
        committed = {path: (PROMPT_ROOT / path).read_bytes() for path in relative_paths}

        with tempfile.TemporaryDirectory() as temporary:
            generated_root = Path(temporary) / "benchmarks" / "prompts"
            shutil.copytree(PROMPT_ROOT, generated_root)
            (generated_root / "manifest.json").write_bytes(b"{}\n")

            first = subprocess.run(
                [sys.executable, str(generated_root / "generate.py"), "--write"],
                cwd=temporary,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            first_outputs = {path: (generated_root / path).read_bytes() for path in relative_paths}
            self.assertEqual(first_outputs, committed)

            second = subprocess.run(
                [sys.executable, str(generated_root / "generate.py"), "--write"],
                cwd=temporary,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(second.returncode, 0, second.stderr)
            second_outputs = {path: (generated_root / path).read_bytes() for path in relative_paths}
            self.assertEqual(second_outputs, first_outputs)

            verify = subprocess.run(
                [sys.executable, str(generated_root / "generate.py")],
                cwd=temporary,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)


if __name__ == "__main__":
    unittest.main()
