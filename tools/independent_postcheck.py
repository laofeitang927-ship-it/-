#!/usr/bin/env python3
"""Independent fail-closed postcheck for two PRWI r6 fresh-extract replays (kit v3)."""
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
PREEXECUTION_STOP_CASES: dict[str, dict[str, Any]] = {
    "mut001-fake-bridge": {
        "kind": "FROZEN_IDENTITY_REJECTION",
        "mutation_id": "MUT-PRWI-012-001",
        "workflow_run_id": "PRWI012-MUT-001",
        "current_workflow_status": "BLOCKED_FROZEN_BRIDGE_IDENTITY",
        "observed_gate": "FROZEN_BRIDGE_IDENTITY_READY",
        "observed_gate_value": "NO",
        "actual_finding_router_execution": False,
        "bridge_mismatch_count": 7,
    },
    "mut002-drift": {
        "kind": "FROZEN_IDENTITY_REJECTION",
        "mutation_id": "MUT-PRWI-012-002",
        "workflow_run_id": "PRWI012-MUT-002",
        "current_workflow_status": "BLOCKED_FROZEN_BRIDGE_IDENTITY",
        "observed_gate": "BRIDGE_IDENTITY_HASH_MISMATCH_COUNT",
        "observed_gate_value": ">=1",
        "actual_finding_router_execution": False,
        "bridge_mismatch_count": 1,
    },
    "r1-mut001-wrong-layer": {
        "kind": "REPAIR_TARGET_CONTRACT_REJECTION",
        "mutation_id": "MUT-PRWI-012R1-001",
        "workflow_run_id": "PRWI012-R1-MUT-001",
        "current_workflow_status": "BLOCKED_REPAIR_TARGET_CONTRACT",
        "observed_gate": "REPAIR_TARGET_CONTRACT_READY",
        "observed_gate_value": "NO",
        "actual_finding_router_execution": True,
        "target_layer": "IR",
        "target_artifact": "OPERATING_BRIEF",
        "finding_id": "R1-MUT-001",
        "target_relative_path": "04-reader/operating-brief.md",
    },
    "r1-mut002-reader-wp": {
        "kind": "REPAIR_TARGET_CONTRACT_REJECTION",
        "mutation_id": "MUT-PRWI-012R1-002",
        "workflow_run_id": "PRWI012-R1-MUT-002",
        "current_workflow_status": "BLOCKED_REPAIR_TARGET_CONTRACT",
        "observed_gate": "REPAIR_TARGET_CONTRACT_READY",
        "observed_gate_value": "NO",
        "actual_finding_router_execution": True,
        "target_layer": "READER",
        "target_artifact": "WORKPAPER",
        "finding_id": "R1-MUT-002",
        "target_relative_path": "02-research/research-workpaper.md",
    },
}
EXPECTED_CURRENT_RUN_RECEIPT_COUNT = 14
EXPECTED_CHILD_TIMEOUT_SECONDS = 18000
EXPECTED_RAW_CASE_EXECUTION_ID_COUNT = 15
EXPECTED_AUTHORITATIVE_CASE_IDENTITY_COUNT = 19
EXPECTED_VERIFIED_PREEXECUTION_STOP_COUNT = 4


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


def positive_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def valid_contract_check(row: Any, expected: dict[str, Any]) -> bool:
    return (
        isinstance(row, dict)
        and row.get("target_layer") == expected["target_layer"]
        and row.get("target_artifact") == expected["target_artifact"]
        and row.get("finding_id") == expected["finding_id"]
        and row.get("layer_known") is True
        and row.get("LAYER_MISMATCH") is True
        and row.get("FORBIDDEN_HIT") is True
        and row.get("READY") is False
    )


def verified_preexecution_identity(
    work: Path,
    case_directory: str,
    result: dict[str, Any],
    receipt_path: Path,
    mutation_rows: dict[str, list[dict[str, Any]]],
    wrong_layer_proofs: list[dict[str, Any]],
) -> tuple[str | None, dict[str, Any], str | None]:
    """Independently recover one real ID from an exact sibling stop receipt."""
    expected = PREEXECUTION_STOP_CASES.get(case_directory)
    receipt_relative = receipt_path.relative_to(work).as_posix()
    evidence = {
        "receipt_relative_path": receipt_relative,
        "receipt_sha256": sha256(receipt_path) if receipt_path.is_file() else None,
        "receipt_version": None,
        "receipt_workflow_run_id": None,
        "receipt_current_workflow_status": None,
        "mutation_id": expected.get("mutation_id") if expected else None,
        "ready": False,
    }
    if expected is None:
        return None, evidence, "CASE_RESULT_MISSING_EXECUTION_ID"
    if not receipt_path.is_file():
        return None, evidence, "PRE_EXECUTION_STOP_RECEIPT_MISSING"
    try:
        receipt_document = load_yaml(receipt_path)
    except Exception:
        return None, evidence, "PRE_EXECUTION_STOP_EVIDENCE_MISMATCH"
    if not isinstance(receipt_document, dict) or set(receipt_document) != {
        "production_research_workflow_receipt"
    }:
        return None, evidence, "PRE_EXECUTION_STOP_EVIDENCE_MISMATCH"
    receipt = receipt_document.get("production_research_workflow_receipt")
    if not isinstance(receipt, dict):
        return None, evidence, "PRE_EXECUTION_STOP_EVIDENCE_MISMATCH"
    evidence.update(
        {
            "receipt_version": receipt.get("version"),
            "receipt_workflow_run_id": receipt.get("workflow_run_id"),
            "receipt_current_workflow_status": receipt.get("current_workflow_status"),
        }
    )
    if receipt.get("workflow_run_id") != expected["workflow_run_id"]:
        return None, evidence, "PRE_EXECUTION_STOP_IDENTITY_MISMATCH"

    rows = mutation_rows.get(expected["mutation_id"], [])
    if len(rows) > 1:
        return None, evidence, "DUPLICATE_MUTATION_EVIDENCE_ROW"
    if len(rows) != 1:
        return None, evidence, "PRE_EXECUTION_STOP_EVIDENCE_MISMATCH"
    mutation = rows[0]
    result_gates = result.get("gates") if isinstance(result.get("gates"), dict) else {}
    receipt_gates = receipt.get("gates") if isinstance(receipt.get("gates"), dict) else {}
    observed_value = mutation.get("observed_gate_value")
    if expected["observed_gate_value"] == ">=1":
        observed_value_ready = positive_integer(observed_value)
    else:
        observed_value_ready = observed_value == expected["observed_gate_value"]
    common_ready = (
        receipt.get("version") == "v0.1.2-r1"
        and receipt.get("current_workflow_status") == expected["current_workflow_status"]
        and result.get("status") == "FAIL"
        and result.get("PRODUCTION_RESEARCH_WORKFLOW_INTEGRATION_READY") == "NO"
        and result_gates.get("PRODUCTION_RESEARCH_WORKFLOW_INTEGRATION_READY") is False
        and receipt_gates.get("PRODUCTION_RESEARCH_WORKFLOW_INTEGRATION_READY") is False
        and mutation.get("mutation_id") == expected["mutation_id"]
        and mutation.get("mutation_type") == expected["mutation_id"]
        and mutation.get("expected_behavior") == "FAIL"
        and isinstance(mutation.get("return_code"), int)
        and not isinstance(mutation.get("return_code"), bool)
        and mutation.get("return_code") != 0
        and mutation.get("actual_orchestrator_execution") is True
        and mutation.get("actual_bridge_execution") is False
        and mutation.get("actual_finding_router_execution")
        is expected["actual_finding_router_execution"]
        and mutation.get("actual_ir_validator_execution") is False
        and mutation.get("actual_reader_regeneration_execution") is False
        and mutation.get("required_execution_satisfied") is True
        and mutation.get("pass") is True
        and mutation.get("observed_gate") == expected["observed_gate"]
        and observed_value_ready
    )
    if not common_ready:
        return None, evidence, "PRE_EXECUTION_STOP_EVIDENCE_MISMATCH"

    if expected["kind"] == "FROZEN_IDENTITY_REJECTION":
        identity = receipt.get("frozen_bridge_identity")
        identity = identity if isinstance(identity, dict) else {}
        result_mismatch = result_gates.get("BRIDGE_IDENTITY_HASH_MISMATCH_COUNT")
        identity_mismatch = identity.get("BRIDGE_IDENTITY_HASH_MISMATCH_COUNT")
        receipt_mismatch = receipt_gates.get("BRIDGE_IDENTITY_HASH_MISMATCH_COUNT")
        evidence_ready = (
            result.get("FROZEN_BRIDGE_IDENTITY_READY") == "NO"
            and result_gates.get("FROZEN_BRIDGE_IDENTITY_READY") is False
            and identity.get("FROZEN_BRIDGE_IDENTITY_READY") is False
            and receipt_gates.get("FROZEN_BRIDGE_IDENTITY_READY") is False
            and positive_integer(result_mismatch)
            and result_mismatch == expected["bridge_mismatch_count"]
            and result_mismatch == identity_mismatch == receipt_mismatch
        )
    else:
        audit = receipt.get("repair_target_contract_audit")
        audit = audit if isinstance(audit, dict) else {}
        expected_gates = {
            "FINDING_ROUTER_EXECUTION_COUNT": 1,
            "REPAIR_TARGET_CONTRACT_READY": False,
            "REPAIR_TARGET_LAYER_MISMATCH_COUNT": 1,
            "FORBIDDEN_REPAIR_TARGET_COUNT": 1,
            "ALL_REPAIR_ACTIONS_MATCH_ROUTER_TARGET_LAYER": False,
            "REPAIR_ACTOR_EXECUTION_COUNT": 0,
        }
        gate_values_ready = all(
            result_gates.get(key) == value and receipt_gates.get(key) == value
            for key, value in expected_gates.items()
        )
        audit_ready = all(
            audit.get(key) == value
            for key, value in expected_gates.items()
            if key not in {"FINDING_ROUTER_EXECUTION_COUNT", "REPAIR_ACTOR_EXECUTION_COUNT"}
        )
        result_checks = result_gates.get("REPAIR_TARGET_CONTRACT_CHECKS")
        audit_checks = audit.get("contract_checks")
        receipt_checks = receipt_gates.get("REPAIR_TARGET_CONTRACT_CHECKS")
        checks_ready = all(
            isinstance(rows_to_check, list)
            and len(rows_to_check) == 1
            and valid_contract_check(rows_to_check[0], expected)
            for rows_to_check in (result_checks, audit_checks, receipt_checks)
        )
        proofs = [
            row
            for row in wrong_layer_proofs
            if isinstance(row, dict) and row.get("mutation_id") == expected["mutation_id"]
        ]
        proof_ready = False
        if len(proofs) == 1:
            proof = proofs[0]
            before = proof.get("target_file_hash_before")
            after = proof.get("target_file_hash_after")
            proof_ready = (
                proof.get("STOP_BEFORE_MUTATION") is True
                and proof.get("STOP_EVIDENCE") == "CONTRACT_GATE_EARLY_RETURN"
                and proof.get("target_relative_path") == expected["target_relative_path"]
                and isinstance(before, str)
                and len(before) == 64
                and all(character in "0123456789abcdef" for character in before)
                and before == after
                and proof.get("REPAIR_ACTOR_EXECUTION_COUNT") == 0
                and proof.get("WRONG_LAYER_MUTATION_COUNT") == 0
                and proof.get("TARGET_FILE_HASH_CHANGED_COUNT") == 0
            )
        evidence_ready = (
            result.get("REPAIR_TARGET_CONTRACT_READY") == "NO"
            and result.get("REPAIR_TARGET_LAYER_MISMATCH_COUNT") == 1
            and result.get("FORBIDDEN_REPAIR_TARGET_COUNT") == 1
            and gate_values_ready
            and audit_ready
            and checks_ready
            and proof_ready
        )
    if not evidence_ready:
        return None, evidence, "PRE_EXECUTION_STOP_EVIDENCE_MISMATCH"
    evidence["ready"] = True
    return expected["workflow_run_id"], evidence, None


def check_receipts(
    work: Path,
    legacy_execution: dict[str, Any],
    wrapper_provenance: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    replay = work / "replay"
    result_paths = sorted(replay.glob("mutation-workdir/*/result.yaml")) if replay.is_dir() else []
    case_ids: set[str] = set()
    case_execution_identities: set[str] = set()
    case_rows: list[dict[str, Any]] = []
    identity_paths: dict[str, list[str]] = {}
    inventory_errors: list[dict[str, Any]] = []
    duplicate_identities: list[dict[str, Any]] = []
    mutation_rows: dict[str, list[dict[str, Any]]] = {}
    mutation_result = replay / "mutation-result.yaml"
    if mutation_result.is_file():
        try:
            mutation_body = load_yaml(mutation_result).get(
                "production_research_workflow_mutation_regression", {}
            )
            for mutation_row in mutation_body.get("cases", []):
                if isinstance(mutation_row, dict) and isinstance(
                    mutation_row.get("mutation_id"), str
                ):
                    mutation_rows.setdefault(mutation_row["mutation_id"], []).append(mutation_row)
        except Exception as exc:
            failures.append(f"MUTATION_RESULT_PARSE_ERROR:{type(exc).__name__}")
    else:
        failures.append("MUTATION_RESULT_MISSING_FOR_IDENTITY_CLOSURE")
    wrong_layer_proofs = legacy_execution.get("wrong_layer_proofs", [])
    if not isinstance(wrong_layer_proofs, list):
        failures.append("WRONG_LAYER_PROOFS_NOT_A_LIST")
        wrong_layer_proofs = []

    for result_path in result_paths:
        case_directory = result_path.parent.name
        relative_path = result_path.relative_to(work).as_posix()
        run_id: str | None = None
        execution_identity: str | None = None
        identity_source: str | None = None
        preexecution_stop = False
        stop_evidence: dict[str, Any] | None = None
        try:
            document = load_yaml(result_path)
            result = document.get("result", document) if isinstance(document, dict) else {}
            if not isinstance(result, dict):
                raise TypeError("result must be a mapping")
            run_id = result.get("workflow_run_id") or result.get("execution_run_id")
            if not isinstance(run_id, str) or not run_id:
                run_id = None
            if case_directory in PREEXECUTION_STOP_CASES:
                recovered_id, stop_evidence, reason = verified_preexecution_identity(
                    work,
                    case_directory,
                    result,
                    result_path.parent / "receipt.yaml",
                    mutation_rows,
                    wrong_layer_proofs,
                )
                if reason:
                    inventory_errors.append({"relative_path": relative_path, "reason": reason})
                    failures.append(f"{reason}:{relative_path}")
                elif run_id is not None and run_id != recovered_id:
                    reason = "PRE_EXECUTION_STOP_IDENTITY_MISMATCH"
                    inventory_errors.append({"relative_path": relative_path, "reason": reason})
                    failures.append(f"{reason}:{relative_path}")
                else:
                    execution_identity = recovered_id
                    preexecution_stop = True
                    identity_source = (
                        "RESULT_AND_VERIFIED_PRE_EXECUTION_RECEIPT"
                        if run_id is not None
                        else "VERIFIED_PRE_EXECUTION_RECEIPT"
                    )
                    if run_id is not None:
                        case_ids.add(run_id)
            elif run_id is not None:
                execution_identity = run_id
                identity_source = "CASE_RESULT"
                case_ids.add(run_id)
            else:
                reason = "CASE_RESULT_MISSING_EXECUTION_ID"
                inventory_errors.append({"relative_path": relative_path, "reason": reason})
                failures.append(f"{reason}:{relative_path}")
        except Exception as exc:
            reason = f"CASE_RESULT_PARSE_ERROR:{type(exc).__name__}"
            inventory_errors.append({"relative_path": relative_path, "reason": reason})
            failures.append(f"{reason}:{relative_path}")
        if execution_identity:
            case_execution_identities.add(execution_identity)
            identity_paths.setdefault(execution_identity, []).append(relative_path)
        case_rows.append(
            {
                "relative_path": relative_path,
                "case_directory": case_directory,
                "execution_run_id": run_id,
                "execution_identity": execution_identity,
                "execution_identity_source": identity_source,
                "preexecution_stop": preexecution_stop,
                "preexecution_stop_evidence": stop_evidence,
            }
        )
    for execution_identity, relative_paths in sorted(identity_paths.items()):
        if len(relative_paths) > 1:
            duplicate = {
                "execution_run_id": execution_identity,
                "relative_paths": relative_paths,
                "reason": "DUPLICATE_CASE_EXECUTION_ID",
            }
            duplicate_identities.append(duplicate)
            inventory_errors.append(duplicate)
            failures.append("DUPLICATE_CASE_EXECUTION_ID:" + execution_identity)

    observed_preexecution_cases = {
        row["case_directory"]
        for row in case_rows
        if row["case_directory"] in PREEXECUTION_STOP_CASES
    }
    if observed_preexecution_cases != set(PREEXECUTION_STOP_CASES):
        failures.append("PREEXECUTION_STOP_CASE_SET_MISMATCH")
    if len(result_paths) != 19:
        failures.append(f"CURRENT_CASE_RESULT_COUNT:{len(result_paths)}!=19")
    raw_result_id_count = sum(row["execution_run_id"] is not None for row in case_rows)
    if raw_result_id_count != EXPECTED_RAW_CASE_EXECUTION_ID_COUNT:
        failures.append(
            f"CURRENT_CASE_RAW_RESULT_ID_COUNT:{raw_result_id_count}"
            f"!={EXPECTED_RAW_CASE_EXECUTION_ID_COUNT}"
        )
    if len(case_ids) != EXPECTED_RAW_CASE_EXECUTION_ID_COUNT:
        failures.append(
            f"CURRENT_CASE_RAW_EXECUTION_ID_COUNT:{len(case_ids)}"
            f"!={EXPECTED_RAW_CASE_EXECUTION_ID_COUNT}"
        )
    if len(case_execution_identities) != EXPECTED_AUTHORITATIVE_CASE_IDENTITY_COUNT:
        failures.append(
            f"CURRENT_CASE_UNIQUE_EXECUTION_IDENTITY_COUNT:{len(case_execution_identities)}"
            f"!={EXPECTED_AUTHORITATIVE_CASE_IDENTITY_COUNT}"
        )
    verified_stop_count = sum(row["preexecution_stop"] for row in case_rows)
    if verified_stop_count != EXPECTED_VERIFIED_PREEXECUTION_STOP_COUNT:
        failures.append(
            f"VERIFIED_PRE_EXECUTION_STOP_COUNT:{verified_stop_count}"
            f"!={EXPECTED_VERIFIED_PREEXECUTION_STOP_COUNT}"
        )
    synthetic_identities = sorted(
        identity
        for identity in case_execution_identities
        if identity.startswith("PREEXECUTION_STOP:")
    )
    if synthetic_identities:
        failures.append("SYNTHETIC_CASE_EXECUTION_IDENTITY_PRESENT")

    expected_wrapper_fields = {
        "AUDIT_RECEIPT_COUNT": EXPECTED_CURRENT_RUN_RECEIPT_COUNT,
        "CURRENT_CASE_RECEIPT_COUNT": EXPECTED_CURRENT_RUN_RECEIPT_COUNT,
        "CURRENT_CASE_EXECUTION_ID_COUNT": EXPECTED_RAW_CASE_EXECUTION_ID_COUNT,
        "CURRENT_CASE_EXECUTION_IDENTITY_COUNT": EXPECTED_AUTHORITATIVE_CASE_IDENTITY_COUNT,
        "CURRENT_CASE_UNIQUE_EXECUTION_IDENTITY_COUNT": EXPECTED_AUTHORITATIVE_CASE_IDENTITY_COUNT,
        "CURRENT_CASE_RESULT_COUNT": EXPECTED_AUTHORITATIVE_CASE_IDENTITY_COUNT,
        "PREEXECUTION_STOP_CASE_COUNT": EXPECTED_VERIFIED_PREEXECUTION_STOP_COUNT,
        "VERIFIED_PRE_EXECUTION_STOP_COUNT": EXPECTED_VERIFIED_PREEXECUTION_STOP_COUNT,
        "DUPLICATE_CASE_EXECUTION_ID_COUNT": 0,
        "FULL_RUN_CLOSED": True,
        "REFERENCE_ANSWER_DEPENDENCY_AUDIT_EXECUTED": True,
        "EXPECTATION_LEAKAGE_METRIC_MACHINE_DERIVED": True,
        "EXPECTATION_LEAKAGE_TEST_COUNT": 0,
        "EXPECTATION_LEAKAGE_FALSE_PASS_COUNT": 0,
        "AUDIT_RECEIPTS_READY": True,
    }
    wrapper_mismatches: list[dict[str, Any]] = []
    if not isinstance(wrapper_provenance, dict):
        wrapper_provenance = {}
    for key, expected_value in expected_wrapper_fields.items():
        actual_value = wrapper_provenance.get(key)
        if actual_value != expected_value:
            wrapper_mismatches.append(
                {"field": key, "expected": expected_value, "actual": actual_value}
            )
            failures.append("WRAPPER_PROVENANCE_FIELD_MISMATCH:" + key)
    if wrapper_provenance.get("case_inventory_errors") != []:
        wrapper_mismatches.append(
            {
                "field": "case_inventory_errors",
                "expected": [],
                "actual": wrapper_provenance.get("case_inventory_errors"),
            }
        )
        failures.append("WRAPPER_CASE_INVENTORY_ERRORS_PRESENT")
    if wrapper_provenance.get("duplicate_case_execution_ids") != []:
        wrapper_mismatches.append(
            {
                "field": "duplicate_case_execution_ids",
                "expected": [],
                "actual": wrapper_provenance.get("duplicate_case_execution_ids"),
            }
        )
        failures.append("WRAPPER_DUPLICATE_CASE_EXECUTION_IDS_PRESENT")

    wrapper_case_rows = {
        row.get("relative_path"): row
        for row in wrapper_provenance.get("case_inventory", [])
        if isinstance(row, dict) and isinstance(row.get("relative_path"), str)
    }
    if len(wrapper_case_rows) != EXPECTED_AUTHORITATIVE_CASE_IDENTITY_COUNT:
        wrapper_mismatches.append(
            {
                "field": "case_inventory_count",
                "expected": EXPECTED_AUTHORITATIVE_CASE_IDENTITY_COUNT,
                "actual": len(wrapper_case_rows),
            }
        )
        failures.append(
            f"WRAPPER_CASE_INVENTORY_COUNT:{len(wrapper_case_rows)}"
            f"!={EXPECTED_AUTHORITATIVE_CASE_IDENTITY_COUNT}"
        )
    comparable_keys = (
        "relative_path",
        "case_directory",
        "execution_run_id",
        "execution_identity",
        "execution_identity_source",
        "preexecution_stop",
    )
    for case_row in case_rows:
        relative_path = case_row["relative_path"]
        wrapper_case_row = wrapper_case_rows.get(relative_path)
        expected_comparable = {key: case_row.get(key) for key in comparable_keys}
        actual_comparable = (
            {key: wrapper_case_row.get(key) for key in comparable_keys}
            if isinstance(wrapper_case_row, dict)
            else None
        )
        if actual_comparable != expected_comparable:
            wrapper_mismatches.append(
                {
                    "field": "case_inventory:" + relative_path,
                    "expected": expected_comparable,
                    "actual": actual_comparable,
                }
            )
            failures.append("WRAPPER_CASE_INVENTORY_MISMATCH:" + relative_path)
    wrapper_synthetic_identities = sorted(
        row.get("execution_identity")
        for row in wrapper_case_rows.values()
        if isinstance(row.get("execution_identity"), str)
        and row["execution_identity"].startswith("PREEXECUTION_STOP:")
    )
    if wrapper_synthetic_identities:
        failures.append("WRAPPER_SYNTHETIC_CASE_EXECUTION_IDENTITY_PRESENT")

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
    selected_relatives = {receipt.relative_to(work).as_posix() for receipt in selected}
    if set(wrapper_rows) != selected_relatives:
        failures.append("WRAPPER_CURRENT_RUN_RECEIPT_INVENTORY_MISMATCH")
        wrapper_mismatches.append(
            {
                "field": "receipts",
                "expected": sorted(selected_relatives),
                "actual": sorted(wrapper_rows),
            }
        )
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
        wrapper_receipt_row_ready = (
            wrapper_row.get("execution_run_id") == body.get("execution_run_id")
            and wrapper_row.get("ready") is True
        )
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
            and wrapper_receipt_row_ready
        )
        if not ready:
            failures.append("CURRENT_RUN_AUDIT_RECEIPT_NOT_READY:" + relative)
        rows.append(
            {
                "relative_path": relative,
                "execution_run_id": body.get("execution_run_id"),
                "run_scoped_receipt_hash": digest,
                "wrapper_receipt_hash_matches": wrapper_hash_ready,
                "wrapper_receipt_row_ready": wrapper_receipt_row_ready,
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
    identity_closure_ready = (
        len(result_paths) == EXPECTED_AUTHORITATIVE_CASE_IDENTITY_COUNT
        and raw_result_id_count == EXPECTED_RAW_CASE_EXECUTION_ID_COUNT
        and len(case_ids) == EXPECTED_RAW_CASE_EXECUTION_ID_COUNT
        and len(case_execution_identities) == EXPECTED_AUTHORITATIVE_CASE_IDENTITY_COUNT
        and verified_stop_count == EXPECTED_VERIFIED_PREEXECUTION_STOP_COUNT
        and not inventory_errors
        and not duplicate_identities
        and not synthetic_identities
        and not wrapper_mismatches
        and not wrapper_synthetic_identities
    )
    return (
        {
            "current_case_result_count": len(result_paths),
            "expected_current_case_result_count": EXPECTED_AUTHORITATIVE_CASE_IDENTITY_COUNT,
            "current_case_raw_result_id_count": raw_result_id_count,
            "current_case_raw_execution_id_count": len(case_ids),
            "expected_current_case_raw_execution_id_count": EXPECTED_RAW_CASE_EXECUTION_ID_COUNT,
            "current_case_unique_execution_id_count": len(case_ids),
            "current_case_authoritative_execution_identity_count": sum(
                bool(row["execution_identity"]) for row in case_rows
            ),
            "current_case_unique_execution_identity_count": len(case_execution_identities),
            "expected_current_case_authoritative_execution_identity_count": (
                EXPECTED_AUTHORITATIVE_CASE_IDENTITY_COUNT
            ),
            "preexecution_stop_case_count": verified_stop_count,
            "verified_preexecution_stop_count": verified_stop_count,
            "expected_verified_preexecution_stop_count": (
                EXPECTED_VERIFIED_PREEXECUTION_STOP_COUNT
            ),
            "duplicate_case_execution_identity_count": len(duplicate_identities),
            "duplicate_case_execution_identities": duplicate_identities,
            "synthetic_case_execution_identity_count": len(synthetic_identities),
            "synthetic_case_execution_identities": synthetic_identities,
            "case_inventory_errors": inventory_errors,
            "case_inventory": case_rows,
            "identity_closure_ready": identity_closure_ready,
            "wrapper_identity_provenance_matches": not wrapper_mismatches,
            "wrapper_identity_provenance_mismatches": wrapper_mismatches,
            "wrapper_synthetic_case_execution_identities": wrapper_synthetic_identities,
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
    if optimized.get("timeout_seconds") != EXPECTED_CHILD_TIMEOUT_SECONDS:
        failures.append(
            f"RUN_{label.upper()}_TIMEOUT_NOT_{EXPECTED_CHILD_TIMEOUT_SECONDS}"
        )

    wrapper_legacy = optimized.get("legacy_execution", {})
    legacy = wrapper_legacy if isinstance(wrapper_legacy, dict) else {}
    if not isinstance(wrapper_legacy, dict):
        failures.append(f"RUN_{label.upper()}_WRAPPER_LEGACY_EXECUTION_NOT_A_MAPPING")
    legacy_artifact_path = evidence / f"run-{label}/legacy-r2-execution.yaml"
    if not legacy_artifact_path.is_file():
        failures.append(f"RUN_{label.upper()}_INDEPENDENT_LEGACY_EXECUTION_MISSING")
    else:
        try:
            legacy_document = load_yaml(legacy_artifact_path)
            if not isinstance(legacy_document, dict) or set(legacy_document) != {
                "r2_portable_execution"
            }:
                raise ValueError("unexpected legacy execution root")
            candidate_legacy = legacy_document.get("r2_portable_execution")
            if not isinstance(candidate_legacy, dict):
                raise TypeError("r2_portable_execution must be a mapping")
            if candidate_legacy != legacy:
                failures.append(f"RUN_{label.upper()}_WRAPPER_LEGACY_EXECUTION_MISMATCH")
        except Exception as exc:
            failures.append(
                f"RUN_{label.upper()}_INDEPENDENT_LEGACY_EXECUTION_PARSE_ERROR:"
                f"{type(exc).__name__}"
            )
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

    provenance, receipt_failures = check_receipts(
        work,
        legacy,
        optimized.get("audit_provenance", {}),
    )
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
            "child_timeout_seconds_per_run": EXPECTED_CHILD_TIMEOUT_SECONDS,
            "fresh_extract_run_count": 2,
            "independent_linux_runner_count": 2,
            "execution_topology": "two independent GitHub-hosted Linux runners; workers=1 per runner",
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
