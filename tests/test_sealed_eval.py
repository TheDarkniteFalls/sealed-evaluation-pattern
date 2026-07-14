from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import sealed_eval


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


class SealedEvaluationTests(unittest.TestCase):
    def test_good_case_passes(self) -> None:
        self.assertEqual(sealed_eval.check_path(EXAMPLES / "good.json"), [])

    def test_expected_bad_cases_fail_with_named_code(self) -> None:
        for name, (_, expected_code) in sealed_eval.SELF_TEST_CASES.items():
            if expected_code is None:
                continue
            with self.subTest(name=name):
                codes = {finding.code for finding in sealed_eval.check_path(EXAMPLES / name)}
                self.assertIn(expected_code, codes)

    def test_unaccessed_sealed_file_is_not_opened(self) -> None:
        case = sealed_eval.load_case(EXAMPLES / "good.json")
        for source in case["sources"]:
            source["path"] = str((EXAMPLES / source["path"]).resolve()) if source["zone"] != "sealed" else "missing-holdout.txt"
        case["generated_output"]["path"] = str((EXAMPLES / case["generated_output"]["path"]).resolve())

        # Absolute paths are rejected by design, so copy only the accessed files
        # into a temporary, self-contained case while leaving the holdout absent.
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            (temp / "sources").mkdir()
            for filename in ("learning-guide.txt", "calibration-gold.txt", "generated-output.txt"):
                (temp / "sources" / filename).write_bytes((EXAMPLES / "sources" / filename).read_bytes())
            for source in case["sources"]:
                source["path"] = f"sources/{Path(source['path']).name}"
            case["generated_output"]["path"] = "sources/generated-output.txt"
            case_path = temp / "case.json"
            case_path.write_text(json.dumps(case), encoding="utf-8")
            self.assertEqual(sealed_eval.check_path(case_path), [])


if __name__ == "__main__":
    unittest.main()
