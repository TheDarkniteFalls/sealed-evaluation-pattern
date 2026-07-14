#!/usr/bin/env python3
"""Validate a declared sealed-evaluation run using only the standard library."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


MAX_CASE_BYTES = 1_000_000
ZONES = {"learning", "calibration", "sealed"}
TOP_LEVEL_FIELDS = {
    "schema_version",
    "evaluation_id",
    "sources",
    "authorized_input_ids",
    "calibration_target_id",
    "generated_output",
    "events",
    "retired_source_ids",
    "contamination_detected",
}


@dataclass(frozen=True)
class Finding:
    code: str
    message: str


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_case(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_CASE_BYTES:
        raise ValueError("case file exceeds one megabyte")
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError("case root must be a JSON object")
    return value


def _safe_path(case_dir: Path, supplied: object) -> Path | None:
    if not isinstance(supplied, str) or not supplied:
        return None
    relative = Path(supplied)
    if relative.is_absolute() or ".." in relative.parts:
        return None
    resolved = (case_dir / relative).resolve()
    try:
        resolved.relative_to(case_dir.resolve())
    except ValueError:
        return None
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _finding(findings: list[Finding], code: str, message: str) -> None:
    findings.append(Finding(code, message))


def validate_case(case: dict[str, Any], case_dir: Path) -> list[Finding]:
    findings: list[Finding] = []

    unknown = sorted(set(case) - TOP_LEVEL_FIELDS)
    missing = sorted(TOP_LEVEL_FIELDS - set(case))
    if unknown:
        _finding(findings, "UNKNOWN_FIELD", f"unknown top-level fields: {', '.join(unknown)}")
    if missing:
        _finding(findings, "MISSING_FIELD", f"missing top-level fields: {', '.join(missing)}")
        return findings

    if case.get("schema_version") != 1:
        _finding(findings, "SCHEMA_VERSION", "schema_version must be 1")
    if not isinstance(case.get("evaluation_id"), str) or not case["evaluation_id"]:
        _finding(findings, "EVALUATION_ID", "evaluation_id must be a non-empty string")

    raw_sources = case.get("sources")
    sources: dict[str, dict[str, Any]] = {}
    if not isinstance(raw_sources, list) or not raw_sources:
        _finding(findings, "SOURCES", "sources must be a non-empty list")
    else:
        for index, source in enumerate(raw_sources):
            if not isinstance(source, dict):
                _finding(findings, "SOURCE_SHAPE", f"source {index} must be an object")
                continue
            source_id = source.get("id")
            zone = source.get("zone")
            if not isinstance(source_id, str) or not source_id:
                _finding(findings, "SOURCE_ID", f"source {index} has an invalid id")
                continue
            if source_id in sources:
                _finding(findings, "DUPLICATE_SOURCE", f"duplicate source id: {source_id}")
                continue
            sources[source_id] = source
            if zone not in ZONES:
                _finding(findings, "SOURCE_ZONE", f"{source_id} has invalid zone: {zone}")
            if _safe_path(case_dir, source.get("path")) is None:
                _finding(findings, "SOURCE_PATH", f"{source_id} has an unsafe path")
            digest = source.get("sha256")
            if not isinstance(digest, str) or len(digest) != 64:
                _finding(findings, "SOURCE_DIGEST", f"{source_id} must declare a SHA-256 digest")

    inputs = case.get("authorized_input_ids")
    if not isinstance(inputs, list) or not inputs or not all(isinstance(item, str) for item in inputs):
        _finding(findings, "AUTHORIZED_INPUTS", "authorized_input_ids must be a non-empty string list")
        inputs = []
    if len(inputs) != len(set(inputs)):
        _finding(findings, "DUPLICATE_INPUT", "authorized_input_ids must be unique")
    for source_id in inputs:
        source = sources.get(source_id)
        if source is None:
            _finding(findings, "UNKNOWN_INPUT", f"authorized input is not declared: {source_id}")
        elif source.get("zone") != "learning":
            _finding(findings, "INPUT_ZONE", f"authorized input is not in learning: {source_id}")

    target_id = case.get("calibration_target_id")
    target = sources.get(target_id) if isinstance(target_id, str) else None
    if target is None:
        _finding(findings, "CALIBRATION_TARGET", "calibration_target_id must name a declared source")
    elif target.get("zone") != "calibration":
        _finding(findings, "CALIBRATION_ZONE", "calibration target must be in calibration")

    raw_events = case.get("events")
    events: list[tuple[str, datetime, dict[str, Any]]] = []
    if not isinstance(raw_events, list):
        _finding(findings, "EVENTS", "events must be a list")
    else:
        for index, event in enumerate(raw_events):
            if not isinstance(event, dict) or not isinstance(event.get("type"), str):
                _finding(findings, "EVENT_SHAPE", f"event {index} must have a string type")
                continue
            at = _timestamp(event.get("at"))
            if at is None:
                _finding(findings, "EVENT_TIME", f"event {index} must use an ISO-8601 UTC timestamp")
                continue
            events.append((event["type"], at, event))

    def event_times(event_type: str) -> list[datetime]:
        return [at for kind, at, _ in events if kind == event_type]

    freeze_times = event_times("output_frozen")
    review_times = event_times("pre_reveal_review")
    reveal_events = [(at, event) for kind, at, event in events if kind == "source_revealed"]
    if len(freeze_times) != 1:
        _finding(findings, "FREEZE_EVENT", "exactly one output_frozen event is required")
    if len(review_times) != 1:
        _finding(findings, "REVIEW_EVENT", "exactly one pre_reveal_review event is required")
    if len(reveal_events) != 1:
        _finding(findings, "REVEAL_EVENT", "exactly one source_revealed event is required")

    reveal_time: datetime | None = None
    if reveal_events:
        reveal_time, reveal_event = reveal_events[0]
        if reveal_event.get("source_id") != target_id:
            _finding(findings, "REVEAL_TARGET", "source_revealed must name the calibration target")
    if freeze_times and review_times and reveal_time is not None:
        if not freeze_times[0] < review_times[0] < reveal_time:
            _finding(findings, "FREEZE_ORDER", "output freeze and review must occur before reveal")

    accessed_ids: set[str] = set()
    for kind, at, event in events:
        if kind != "source_access":
            continue
        source_id = event.get("source_id")
        if not isinstance(source_id, str) or source_id not in sources:
            _finding(findings, "ACCESS_SOURCE", f"source_access names unknown source: {source_id}")
            continue
        accessed_ids.add(source_id)
        zone = sources[source_id].get("zone")
        if zone == "sealed":
            _finding(findings, "SEALED_ACCESS", f"sealed source was accessed: {source_id}")
        if zone == "calibration" and (reveal_time is None or at < reveal_time):
            _finding(findings, "PRE_REVEAL_ACCESS", f"calibration source accessed before reveal: {source_id}")
        if zone == "calibration" and source_id != target_id:
            _finding(findings, "WRONG_CALIBRATION", f"non-target calibration source was accessed: {source_id}")

    for source_id in inputs:
        if source_id not in accessed_ids:
            _finding(findings, "INPUT_NOT_ACCESSED", f"authorized input has no access event: {source_id}")

    retired = case.get("retired_source_ids")
    if not isinstance(retired, list) or not all(isinstance(item, str) for item in retired):
        _finding(findings, "RETIRED_SOURCES", "retired_source_ids must be a string list")
        retired = []
    if target_id not in retired:
        _finding(findings, "REVEALED_NOT_RETIRED", "revealed calibration target must be retired")
    for source_id in retired:
        if source_id not in sources:
            _finding(findings, "UNKNOWN_RETIRED", f"retired source is not declared: {source_id}")

    if case.get("contamination_detected") is not False:
        _finding(findings, "CONTAMINATION_DECLARED", "a contaminated run cannot support a blind claim")

    generated = case.get("generated_output")
    if not isinstance(generated, dict):
        _finding(findings, "GENERATED_OUTPUT", "generated_output must be an object")
    else:
        output_path = _safe_path(case_dir, generated.get("path"))
        expected = generated.get("sha256")
        if output_path is None:
            _finding(findings, "OUTPUT_PATH", "generated output path is unsafe")
        elif not output_path.is_file():
            _finding(findings, "OUTPUT_MISSING", "generated output file is missing")
        elif not isinstance(expected, str) or _sha256(output_path) != expected:
            _finding(findings, "OUTPUT_DIGEST_MISMATCH", "generated output digest does not match")

    # Deliberately hash only material declared as accessed. A sealed source is
    # not opened merely to prove that the validator avoided opening it.
    for source_id in sorted(accessed_ids):
        source = sources.get(source_id)
        if source is None or source.get("zone") == "sealed":
            continue
        source_path = _safe_path(case_dir, source.get("path"))
        if source_path is None or not source_path.is_file():
            _finding(findings, "ACCESSED_SOURCE_MISSING", f"accessed source is missing: {source_id}")
        elif _sha256(source_path) != source.get("sha256"):
            _finding(findings, "SOURCE_DIGEST_MISMATCH", f"source digest does not match: {source_id}")

    return findings


def check_path(path: Path) -> list[Finding]:
    try:
        case = load_case(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [Finding("CASE_LOAD", str(exc))]
    return validate_case(case, path.parent)


SELF_TEST_CASES = {
    "good.json": (True, None),
    "bad_sealed_access.json": (False, "SEALED_ACCESS"),
    "bad_freeze_order.json": (False, "FREEZE_ORDER"),
    "bad_output_hash.json": (False, "OUTPUT_DIGEST_MISMATCH"),
    "bad_unretired_gold.json": (False, "REVEALED_NOT_RETIRED"),
    "bad_unauthorized_input.json": (False, "INPUT_ZONE"),
}


def run_self_test(root: Path) -> int:
    failures = 0
    for name, (should_pass, expected_code) in SELF_TEST_CASES.items():
        findings = check_path(root / "examples" / name)
        codes = {finding.code for finding in findings}
        passed = not findings
        correct = passed == should_pass and (expected_code is None or expected_code in codes)
        print(f"{'PASS' if correct else 'FAIL'} fixture {name}")
        failures += not correct
    if failures:
        print(f"FAIL self_test {failures} fixture expectations failed")
        return 1
    print("PASS self_test")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", nargs="?", type=Path, help="path to a sealed-evaluation case JSON file")
    parser.add_argument("--self-test", action="store_true", help="run bundled pass/fail fixtures")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    if args.self_test:
        return run_self_test(root)
    if args.case is None:
        parser.error("provide a case path or --self-test")

    path = args.case.resolve()
    findings = check_path(path)
    if findings:
        for finding in findings:
            print(f"FAIL {finding.code} {finding.message}")
        return 1
    print(f"PASS sealed_evaluation {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
