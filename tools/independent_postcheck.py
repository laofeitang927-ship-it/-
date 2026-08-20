#!/usr/bin/env python3
"""Independent fail-closed postcheck for two PRWI r5 fresh-extract replays (kit v3)."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import unicodedata
from pathlib import Path
from typing import Any

import yaml


RECEIPT_NAME = "reference-answer-dependency-audit-receipt-v0.3.2-r1.yaml"
AUDIT_COUNT_FIELDS = (
    "CERTIFIED_IR_RUNTIME_DEPENDENCY_COUNT",
    "CERTIFIED_READER_RUNTIME_DEPENDENCY_COUNT",
    "HARDCODED_FIXTURE_FINDING_ID_COUNT",
    "PRECOMPUTED_COMPARISON_VERDICT_DEPENDENCY_COUNT",
    "EXECUTABLE_PROBE_FAILURE_COUNT",
)
C01_EXPECTED = {
    "BEFORE_TARGET_GAP_EXISTS": True,
    "BEFORE_EXPECTED_KNOWLEDGE_PRESENT_IN_IR": False,
    "AFTER_TARGET_GAP_EXISTS": False,
    "AFTER_EXPECTED_KNOWLEDGE_PRESENT_IN_IR": True,
    "TARGETED_SEMANTIC_IDENTITY_MATCH": True,
    "TARGETED_IR_GAP_CLOSURE_READY": True,
}
MUTATION_EXPECTED = {
    "EXPECTED_REAL_PRODUCTION_MUTATION_COUNT": 19,
    "ACTUAL_REAL_PRODUCTION_MUTATION_COUNT": 19,
    "REAL_PRODUCTION_MUTATION_PASS_COUNT": 19,
    "REAL_PRODUCTION_MUTATION_FAIL_COUNT": 0,
    "SCAFFOLD_ONLY_TEST_COUNT": 0,
}
PREEXECUTION_STOP_CASES = {
    "mut001-fake-bridge",
    "mut002-drift",
    "r1-mut001-wrong-layer",
    "r1-mut002-reader-wp",
}
EXPECTED_CURRENT_RUN_RECEIPT_COUNT = 14


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dump_yaml(value: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(value, allow_unicode=True, sort_keys=False, width=180),
        encoding="utf-8",
    )


def read_rc(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def scoped_file(root: Path, filename: str, run_id: str | None) -> Path | None:
    matches = sorted(root.rglob(filename)) if root.is_dir() else []
    if run_id:
        scoped = [path for path in matches if run_id in path.parts]
        if len(scoped) == 1:
            return scoped[0]
    return matches[0] if len(matches) == 1 else None


def normalize_scalar(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = unicodedata.normalize("NFC", value)
    text = re.sub(r"\s+", " ", text).strip().lower()
    text = text.replace("，", ",")
    text = re.sub(r"(?<=\d),(?=\d)", "", text)
    return text


def normalize_projection(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: normalize_projection(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [normalize_projection(item) for item in value]
    return normalize_scalar(value)


def canonical_projection(work: Path, gates: dict[str, Any], run_id: str | None) -> tuple[dict[str, Any], str, list[str]]:
    failures: list[str] = []
    c01_root = work / "replay/mutation-workdir/mut008-gap-request"
    before_path = scoped_file(c01_root, "ir-gap-before-state-v0.1.yaml", run_id)
    after_path = scoped_file(c01_root, "ir-gap-after-state-v0.1.yaml", run_id)
    before_document = load_yaml(before_path) if before_path else {}
    after_document = load_yaml(after_path) if after_path else {}

    def single_state(document: Any, root_key: str, label: str) -> dict[str, Any]:
        body = document.get(root_key, document) if isinstance(document, dict) else {}
        states = body.get("states", []) if isinstance(body, dict) else []
        if not isinstance(states, list) or len(states) != 1 or not isinstance(states[0], dict):
            failures.append(f"C01_{label}_STATE_COUNT_NOT_ONE")
            return {}
        return states[0]

    before = single_state(before_document, "ir_gap_before_state", "BEFORE")
    after = single_state(after_document, "ir_gap_after_state", "AFTER")
    before_identity = before.get("knowledge_identity", {}) if isinstance(before, dict) else {}
    after_identity = after.get("knowledge_identity", {}) if isinstance(after, dict) else {}

    gap_id = before.get("gap_id") if isinstance(before, dict) else None
    expected_type = before_identity.get("expected_ir_object_type")
    expected_knowledge = before_identity.get("normalized_expected")
    fingerprint = before.get("targeted_semantic_fingerprint") if isinstance(before, dict) else None
    if isinstance(after, dict):
        if after.get("gap_id") != gap_id:
            failures.append("C01_GAP_ID_CHANGED_BETWEEN_BEFORE_AND_AFTER")
        if after.get("targeted_semantic_fingerprint") != fingerprint:
            failures.append("C01_FINGERPRINT_CHANGED_BETWEEN_BEFORE_AND_AFTER")
    if isinstance(after_identity, dict):
        if after_identity.get("expected_ir_object_type") != expected_type:
            failures.append("C01_EXPECTED_OBJECT_TYPE_CHANGED_BETWEEN_BEFORE_AND_AFTER")
        if after_identity.get("normalized_expected") != expected_knowledge:
            failures.append("C01_EXPECTED_KNOWLEDGE_CHANGED_BETWEEN_BEFORE_AND_AFTER")

    projection: dict[str, Any] = {key: gates.get(key) for key in C01_EXPECTED}
    projection.update(
        {
            "gap_id": gap_id,
            "expected_ir_object_type": expected_type,
            "expected_knowledge": expected_knowledge,
            "targeted_semantic_fingerprint": fingerprint,
        }
    )
    missing = [key for key, value in projection.items() if value is None]
    if missing:
        failures.append("CANONICAL_SEMANTIC_FIELDS_MISSING:" + ",".join(sorted(missing)))
    normalized = normalize_projection(projection)
    serialized = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return {"raw": projection, "normalized": normalized, "serialization": serialized}, digest, failures


def copy_evidence(work: Path, evidence: Path, label: str) -> None:
    destination = evidence / "selected-run-evidence" / label
    candidates = [
        work / "certification.yaml",
        work / "replay/mutation-result.yaml",
        work / "replay/verification.yaml",
        work / "replay/mutation-workdir/mut008-gap-request/result.yaml",
    ]
    replay = work / "replay"
    if replay.is_dir():
        candidates.extend(sorted(replay.glob("mutation-workdir/*/result.yaml")))
        candidates.extend(sorted(replay.rglob(RECEIPT_NAME)))
        c01 = replay / "mutation-workdir/mut008-gap-request"
        for name in (
            "ir-gap-before-state-v0.1.yaml",
            "ir-gap-after-state-v0.1.yaml",
            "ir-gap-requests-v0.3.2.yaml",
            "candidate-ir-v0.3.2.yaml",
            "finding-repair-execution-receipt-v0.2.yaml",
        ):
            candidates.extend(sorted(c01.rglob(name)))
        workpaper = c01 / "package/02-research/research-workpaper.md"
        candidates.append(workpaper)
    seen: set[Path] = set()
    for source in candidates:
        if not source.is_file() or source in seen:
            continue
        seen.add(source)
        relative = source.relative_to(work)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def check_receipts(work: Path, wrapper_provenance: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    replay = work / "replay"
    result_paths = sorted(replay.glob("mutation-workdir/*/result.yaml")) if replay.is_dir() else []
    case_ids: set[str] = set()
    case_execution_identities: set[str] = set()
    case_rows: list[dict[str, Any]] = []
    for result_path in result_paths:
        case_directory = result_path.parent.name
        try:
            document = load_yaml(result_path)
            result = document.get("result", document) if isinstance(document, dict) else {}
            run_id = result.get("workflow_run_id") or result.get("execution_run_id")
        except Exception as exc:
            run_id = None
            failures.append(f"CASE_RESULT_PARSE_ERROR:{result_path.name}:{type(exc).__name__}")
        if not isinstance(run_id, str) or not run_id:
            run_id = None
            if case_directory not in PREEXECUTION_STOP_CASES:
                failures.append("CASE_RESULT_MISSING_EXECUTION_ID:" + result_path.relative_to(work).as_posix())
            execution_identity = "PREEXECUTION_STOP:" + case_directory
        else:
            case_ids.add(run_id)
            execution_identity = run_id
        if execution_identity in case_execution_identities:
            failures.append("CASE_RESULT_DUPLICATE_EXECUTION_IDENTITY:" + execution_identity)
        case_execution_identities.add(execution_identity)
        case_rows.append(
            {
                "path": result_path.relative_to(work).as_posix(),
                "case_directory": case_directory,
                "execution_id": run_id,
                "execution_identity": execution_identity,
                "preexecution_stop": case_directory in PREEXECUTION_STOP_CASES,
            }
        )
    if len(result_paths) != 19:
        failures.append(f"CURRENT_CASE_RESULT_COUNT:{len(result_paths)}!=19")
    if len(case_execution_identities) != 19:
        failures.append(f"CURRENT_CASE_UNIQUE_EXECUTION_IDENTITY_COUNT:{len(case_execution_identities)}!=19")

    receipts = sorted(replay.rglob(RECEIPT_NAME)) if replay.is_dir() else []
    selected: list[Path] = []
    excluded: list[dict[str, Any]] = []
    for receipt in receipts:
        try:
            body = load_yaml(receipt).get("reference_answer_dependency_audit", {})
        except Exception:
            body = {}
        run_id = body.get("execution_run_id")
        parts = receipt.relative_to(work).parts
        if "mut002-drift" in parts:
            excluded.append({"path": receipt.relative_to(work).as_posix(), "reason": "COPIED_HISTORICAL_RECEIPT"})
        elif not run_id:
            excluded.append({"path": receipt.relative_to(work).as_posix(), "reason": "MISSING_EXECUTION_ID"})
        elif run_id not in case_ids:
            excluded.append({"path": receipt.relative_to(work).as_posix(), "reason": "NOT_IN_CURRENT_CASE_INVENTORY"})
        else:
            selected.append(receipt)
    if not selected:
        failures.append("NO_CURRENT_RUN_AUDIT_RECEIPTS")
    if len(selected) != EXPECTED_CURRENT_RUN_RECEIPT_COUNT:
        failures.append(
            f"CURRENT_RUN_AUDIT_RECEIPT_COUNT:{len(selected)}!={EXPECTED_CURRENT_RUN_RECEIPT_COUNT}"
        )

    wrapper_rows = {
        row.get("relative_path"): row
        for row in wrapper_provenance.get("receipts", [])
        if isinstance(row, dict) and row.get("relative_path")
    }
    rows: list[dict[str, Any]] = []
    for receipt in selected:
        relative = receipt.relative_to(work).as_posix()
        digest = sha256(receipt)
        try:
            body = load_yaml(receipt).get("reference_answer_dependency_audit", {})
            parsed = True
        except Exception as exc:
            body = {}
            parsed = False
            failures.append(f"AUDIT_RECEIPT_PARSE_ERROR:{relative}:{type(exc).__name__}")
        counts = body.get("counts", {}) if isinstance(body, dict) else {}
        counts_ready = all(counts.get(key) == 0 for key in AUDIT_COUNT_FIELDS)
        probes_ready = all(row.get("help_probe_return_code") == 0 for row in body.get("scripts", []))
        scripts_ready = True
        script_mismatch: list[dict[str, Any]] = []
        for script, expected in body.get("audited_script_sha256", {}).items():
            marker = "/ir-root/"
            if marker not in script:
                scripts_ready = False
                script_mismatch.append({"path": script, "reason": "NO_IR_ROOT_MARKER"})
                continue
            runtime_file = work / "ir-root" / script.split(marker, 1)[1]
            actual = sha256(runtime_file) if runtime_file.is_file() else None
            if actual != expected:
                scripts_ready = False
                script_mismatch.append({"path": script, "expected": expected, "actual": actual})
        wrapper_row = wrapper_rows.get(relative, {})
        wrapper_hash_ready = wrapper_row.get("receipt_sha256") == digest
        ready = (
            parsed
            and body.get("version") == "v0.3.2-r1"
            and body.get("execution_run_id") in case_ids
            and body.get("REFERENCE_ANSWER_DEPENDENCY_AUDIT_READY") is True
            and body.get("issues") == []
            and counts_ready
            and probes_ready
            and scripts_ready
            and wrapper_hash_ready
        )
        if not ready:
            failures.append("CURRENT_RUN_AUDIT_RECEIPT_NOT_READY:" + relative)
        rows.append(
            {
                "relative_path": relative,
                "execution_run_id": body.get("execution_run_id"),
                "run_scoped_receipt_hash": digest,
                "wrapper_receipt_hash_matches": wrapper_hash_ready,
                "counts": counts,
                "counts_ready": counts_ready,
                "executable_probes_ready": probes_ready,
                "audited_script_hashes_ready": scripts_ready,
                "script_mismatch": script_mismatch,
                "ready": ready,
            }
        )
    total_leakage = sum(
        sum(row["counts"].get(key, 0) for key in AUDIT_COUNT_FIELDS)
        for row in rows
    )
    false_pass = sum(not row["ready"] for row in rows)
    return (
        {
            "current_case_result_count": len(result_paths),
            "current_case_unique_execution_id_count": len(case_ids),
            "current_case_unique_execution_identity_count": len(case_execution_identities),
            "preexecution_stop_case_count": sum(row["preexecution_stop"] for row in case_rows),
            "case_inventory": case_rows,
            "current_run_receipt_count": len(rows),
            "expected_current_run_receipt_count": EXPECTED_CURRENT_RUN_RECEIPT_COUNT,
            "excluded_receipts": excluded,
            "EXPECTATION_LEAKAGE_TEST_COUNT": total_leakage,
            "EXPECTATION_LEAKAGE_FALSE_PASS_COUNT": false_pass,
            "receipts": rows,
        },
        failures,
    )


def check_one(label: str, work: Path, result_path: Path, evidence: Path) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    rc = read_rc(evidence / f"run-{label}/run-return-code.txt")
    if rc != 0:
        failures.append(f"RUN_{label.upper()}_RETURN_CODE:{rc}")
    if not result_path.is_file():
        failures.append(f"RUN_{label.upper()}_RESULT_MISSING")
        return {"label": label, "return_code": rc, "ready": False}, failures
    try:
        optimized = load_yaml(result_path).get("optimized_r2_portable_execution", {})
    except Exception as exc:
        failures.append(f"RUN_{label.upper()}_RESULT_PARSE_ERROR:{type(exc).__name__}")
        return {"label": label, "return_code": rc, "ready": False}, failures

    if optimized.get("OPTIMIZED_EXECUTION_READY") is not True:
        failures.append(f"RUN_{label.upper()}_OPTIMIZED_EXECUTION_NOT_READY")
    if optimized.get("supervisor_timed_out") is not False:
        failures.append(f"RUN_{label.upper()}_SUPERVISOR_TIMED_OUT")
    if optimized.get("timeout_seconds") != 3600:
        failures.append(f"RUN_{label.upper()}_TIMEOUT_NOT_3600")

    legacy = optimized.get("legacy_execution", {})
    if legacy.get("R2_EXECUTION_READY") is not True:
        failures.append(f"RUN_{label.upper()}_LEGACY_EXECUTION_NOT_READY")
    mutation = legacy.get("mutation", {})
    mutation_failures = [key for key, expected in MUTATION_EXPECTED.items() if mutation.get(key) != expected]
    if mutation_failures:
        failures.append(f"RUN_{label.upper()}_MUTATION_19_OF_19_FAILED:" + ",".join(mutation_failures))

    mutation_path = work / "replay/mutation-result.yaml"
    mutation_receipt = {}
    if mutation_path.is_file():
        mutation_receipt = load_yaml(mutation_path).get("production_research_workflow_mutation_regression", {})
        independent_mutation_failures = [
            key for key, expected in MUTATION_EXPECTED.items() if mutation_receipt.get(key) != expected
        ]
        if independent_mutation_failures:
            failures.append(
                f"RUN_{label.upper()}_INDEPENDENT_MUTATION_RECEIPT_FAILED:"
                + ",".join(independent_mutation_failures)
            )
    else:
        failures.append(f"RUN_{label.upper()}_MUTATION_RESULT_MISSING")

    c01 = legacy.get("c01", {})
    c01_failures = [key for key, expected in C01_EXPECTED.items() if c01.get(key) is not expected]
    if c01_failures:
        failures.append(f"RUN_{label.upper()}_C01_GATE_FAILURE:" + ",".join(c01_failures))
    c01_result_path = work / "replay/mutation-workdir/mut008-gap-request/result.yaml"
    c01_result = load_yaml(c01_result_path).get("result", {}) if c01_result_path.is_file() else {}
    independent_gates = c01_result.get("gates", {}) if isinstance(c01_result, dict) else {}
    independent_c01_failures = [
        key for key, expected in C01_EXPECTED.items() if independent_gates.get(key) is not expected
    ]
    if independent_c01_failures:
        failures.append(
            f"RUN_{label.upper()}_INDEPENDENT_C01_GATE_FAILURE:"
            + ",".join(independent_c01_failures)
        )
    run_id = c01_result.get("workflow_run_id") if isinstance(c01_result, dict) else None

    artifact_rows: dict[str, Any] = {}
    for name, row in legacy.get("c01_artifacts", {}).items():
        relative = row.get("relative_path") if isinstance(row, dict) else None
        path = work / relative if relative else None
        actual = sha256(path) if path and path.is_file() else None
        hash_ready = bool(path and path.is_file() and actual == row.get("sha256"))
        if not hash_ready:
            failures.append(f"RUN_{label.upper()}_C01_ARTIFACT_HASH_FAILURE:{name}")
        artifact_rows[name] = {
            "relative_path": relative,
            "expected_sha256": row.get("sha256") if isinstance(row, dict) else None,
            "actual_sha256": actual,
            "ready": hash_ready,
        }
    if set(artifact_rows) != {"before_state", "after_state", "gap_registry", "candidate_ir", "repair_receipt", "workpaper"}:
        failures.append(f"RUN_{label.upper()}_C01_ARTIFACT_SET_INCOMPLETE")

    provenance, receipt_failures = check_receipts(work, optimized.get("audit_provenance", {}))
    failures.extend(f"RUN_{label.upper()}_{failure}" for failure in receipt_failures)
    projection, semantic_hash, semantic_failures = canonical_projection(work, independent_gates, run_id)
    failures.extend(f"RUN_{label.upper()}_{failure}" for failure in semantic_failures)
    (evidence / f"canonical-semantic-projection-{label}.json").write_text(
        json.dumps(projection, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    copy_evidence(work, evidence, label)
    return (
        {
            "label": label,
            "return_code": rc,
            "optimized_execution_ready": optimized.get("OPTIMIZED_EXECUTION_READY"),
            "supervisor_timed_out": optimized.get("supervisor_timed_out"),
            "timeout_seconds": optimized.get("timeout_seconds"),
            "mutation": mutation,
            "independent_mutation_receipt": {
                key: mutation_receipt.get(key) for key in MUTATION_EXPECTED
            },
            "c01": c01,
            "c01_artifacts": artifact_rows,
            "audit_provenance": provenance,
            "canonical_semantic_hash": semantic_hash,
            "canonical_semantic_projection": projection["normalized"],
            "ready": not failures,
        },
        failures,
    )


def write_sha_manifest(evidence: Path) -> None:
    manifest = evidence / "SHA256SUMS"
    rows = []
    for path in sorted(p for p in evidence.rglob("*") if p.is_file() and p != manifest):
        rows.append(f"{sha256(path)}  {path.relative_to(evidence).as_posix()}")
    manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-a", required=True)
    parser.add_argument("--work-b", required=True)
    parser.add_argument("--result-a", required=True)
    parser.add_argument("--result-b", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    evidence = Path(args.evidence_dir).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    run_a, failures_a = check_one("a", Path(args.work_a).resolve(), Path(args.result_a).resolve(), evidence)
    run_b, failures_b = check_one("b", Path(args.work_b).resolve(), Path(args.result_b).resolve(), evidence)
    failures = failures_a + failures_b

    hash_a = run_a.get("canonical_semantic_hash")
    hash_b = run_b.get("canonical_semantic_hash")
    cross_run_stable = bool(hash_a and hash_b and hash_a == hash_b)
    if not cross_run_stable:
        failures.append("CROSS_RUN_CANONICAL_SEMANTIC_HASH_NOT_STABLE")
    structure_rc = read_rc(evidence / "structure-verification/return-code.txt")
    structure_path = evidence / "structure-verification/result.yaml"
    structure_doc = load_yaml(structure_path) if structure_path.is_file() else {}
    structure_body = structure_doc.get("optimized_r2_verification", {})
    structure_ready = (
        structure_rc == 0
        and structure_body.get("baseline", {}).get("ready") is True
        and structure_body.get("sources", {}).get("ready") is True
        and structure_body.get("frozen", {}).get("ready") is True
        and structure_body.get("negative_controls_ready") is True
    )
    if not structure_ready:
        failures.append("OPTIMIZED_R2_STRUCTURE_VERIFICATION_FAILED")

    passed = not failures
    report = {
        "independent_external_revalidation": {
            "decision": "PASS" if passed else "FAIL",
            "OPTIMIZED_R2_CANDIDATE_READY": "YES" if passed else "NO",
            "CURRENT_R1_EXTERNAL_REVALIDATION": "FAIL",
            "CURRENT_R2_EXTERNAL_REVALIDATION": "PASS",
            "INDEPENDENT_EXTERNAL_REVALIDATION_REQUIRED": "NO" if passed else "YES",
            "FIXTURE2_ALLOWED_TO_START": "NO",
            "LEARNING_COMPILE_PRODUCTION_INTEGRATION_ALLOWED": "NO",
            "FROZEN_CORE_REOPEN_REQUIRED": "NO",
            "workers_per_run": 1,
            "child_timeout_seconds_per_run": 3600,
            "serial_fresh_extract_run_count": 2,
            "mutation_requirement": "19/19 for each run",
            "structure_verification_ready": structure_ready,
            "cross_run_semantic_hash_stability": {
                "required": True,
                "run_a_canonical_semantic_hash": hash_a,
                "run_b_canonical_semantic_hash": hash_b,
                "stable": cross_run_stable,
            },
            "run_a": run_a,
            "run_b": run_b,
            "failure_count": len(failures),
            "failures": failures,
        }
    }
    out = Path(args.out).resolve()
    dump_yaml(report, out)
    write_sha_manifest(evidence)
    print("INDEPENDENT_EXTERNAL_REVALIDATION =", "PASS" if passed else "FAIL")
    print("OPTIMIZED_R2_CANDIDATE_READY =", "YES" if passed else "NO")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
