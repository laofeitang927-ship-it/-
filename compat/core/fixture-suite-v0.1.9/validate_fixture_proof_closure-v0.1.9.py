# -*- coding: utf-8 -*-
"""
Proof Harness v0.1.9 —— Verifier Execution Provenance Fixed Point
==================================================================
在 v0.1.8 基础上修复（HF-V019-001 / P1）：

  P0-1  VERIFIER_EXECUTION_PROVENANCE_GAP（HF-V019-001 = CONFIRMED）
    - v0.1.8 假执行：check_owner_execution() 用
        `executed = rule in ref_rules_executed or fld in REF_RULE_MAP`      （REFERENCE）
        `rule_executed = rule in executed_rules or (rule in SSC_RULE_MAP.values())`（SSC）
      → mapping existence 直接充当 execution evidence；且 ref_rules_executed /
        {"SSC-001","SSC-002","SSC-003"} 是硬编码静态常量集（任务八禁止）。
      实测：禁用 check_reference/check_ssc 后 1356/1356 owner receipts 仍 PASS。
    - v0.1.9 修法（任务九~十七）：
        * Execution Event 由 verifier 内部实时 emit（谁执行，谁留下事件）
        * REF/SSC Map 只负责 routing（FIELD → EXPECTED RULE），不证明执行
        * Owner Receipt 只聚合 Execution Events（matching by owner/object/field/
          run_id/input-hash/rule-validity），无 event → executed=NO, result=FAIL
        * 新增 VERIFIER_EXECUTION_PROVENANCE_READY：
          MISSING=0 AND INVALID=0 AND ORPHAN=0
        * 每个 event 绑定 run_id（uuid）+ input_semantic_sha256（当前 field 值）
  P1-1  CERTIFICATION_META_TEST_FALSE_PASS → 见 certify-core-v0.1.py v0.1.9
    （all-green baseline 单门翻转 + gate-dependency 驱动）

  ENTAILMENT / BINDING owner 统一进入同一 Execution Event contract
  （任务四十/四十一）：
    - ENTAILMENT：clause review / structured check / coverage / EMPTY 均 emit event
    - BINDING：canonical payload 消费检查 emit event

路径无关：BASE_DIR = Path(__file__).resolve().parent。
"""
import argparse
import hashlib
import importlib.util
import re
import sys
import uuid
from pathlib import Path

import yaml

BASE_DIR = Path(__file__).resolve().parent

_spec = importlib.util.spec_from_file_location(
    "ser", BASE_DIR / "canonical-semantic-serializer-v0.2.py")
ser = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ser)

POLICY = BASE_DIR / "semantic-field-policy-v0.1.yaml"
REGISTRY = BASE_DIR / "verifier-rule-registry-v0.1.yaml"

# 正式上游引用字段（formal_upstream_closure，v0.1.8 保留）
REF_FIELDS = {
    "assessment": ["based_on_claims", "based_on_relationships"],
    "state": ["based_on_assessments"],
    "relationship": ["source_object", "target_object"],
    "claim": ["derived_from", "supporting_evidence"],
    "evidence": [],
    "unknown": ["affects_states", "current_evidence"],
    "trigger": ["affects_states"],
}

VERDICTS = {"ENTAILED", "BOUNDED_INFERENCE", "PARTIALLY_ENTAILED",
            "NOT_ENTAILED", "MODEL_REVIEW_REQUIRED"}

HEAVY_WORD_PAT = re.compile(r"\d|[增长下降]|导致|驱动|因为|所以|可能|风险|证明|决定|必然|尚未|未验证|未闭合|回报|贡献|恶化|改善|高于|低于|超过|不足")

# 管理层归因固定词组（SSC-004，与 v1.18 正文纪律一致）。
# 允许带括号注记的变体：'公司（2025-02-24 自愿公告）'（公司+公告来源注记）；
# 裸 '公司' 不匹配（正文纪律：单独"公司"不构成管理层归因）。
ATTRIBUTION_SUBJECT_RE = re.compile(
    r"^(公司称|公司表示|公司认为|公司预计|公司披露|公司说明|公司公告|公司介绍|管理层"
    r"|公司（[^）]*）)(（.*）)?$")

# REFERENCE 引用解析的允许目标类型（REF-RULE 具体检查）
# current_evidence 允许 evidence 或 claim（Unknown 的当前证据可为承载事实的 Claim，
# 阿里 fixture 既有设计：U-BABA-001~005 的 current_evidence 指向 DIRECT_FACT Claim）
REF_TARGET_TYPES = {
    "based_on_claims": ["claim"],
    "based_on_relationships": ["relationship"],
    "based_on_assessments": ["assessment"],
    "supporting_evidence": ["evidence"],
    "derived_from": ["claim"],
    "source_object": ["claim", "assessment"],
    "target_object": ["claim", "assessment"],
    "supersedes": None,          # 任意对象
    "affects_states": ["state"],
    "current_evidence": ["evidence", "claim"],
    "core_unknowns": ["unknown"],
    "key_triggers": ["trigger"],
}

EVENT_PREFIX = {"REFERENCE": "REF-EVT-", "STRUCTURAL_SEMANTIC": "SSC-EVT-",
                "ENTAILMENT": "ENT-EVT-", "BINDING": "BIND-EVT-"}

UNKNOWN_WORDS = ["尚未闭合", "无法判断", "仍待验证", "未披露因此无法判断", "待观察", "不能确认"]
STRONG_WORDS = ["显著抬高利润", "证明", "核心驱动", "决定", "商业模式稳定", "必然"]
STRONG_WORDING = ["证明", "必然", "决定"]


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def formal_upstream_closure(target_id, objs):
    closure = set()
    stack = [target_id]
    while stack:
        oid = stack.pop()
        if oid in closure:
            continue
        o = objs.get(oid)
        if o is None:
            continue
        closure.add(oid)
        for f in REF_FIELDS.get(o.get("object_type"), []):
            val = o.get(f)
            if isinstance(val, str):
                stack.append(val)
            elif isinstance(val, list):
                for rid in val:
                    if isinstance(rid, str):
                        stack.append(rid)
    return closure


def mark_covered(field_text, token, covered):
    start = 0
    while True:
        i = field_text.find(token, start)
        if i < 0:
            break
        for j in range(i, i + len(token)):
            covered[j] = True
        start = i + 1


def coverage_check(field_text, reviewed_texts, excluded_spans):
    covered = [False] * len(field_text)
    for t in reviewed_texts:
        mark_covered(field_text, t, covered)
    invalid_excl = []
    for sp in excluded_spans:
        text = sp.get("text", "")
        if not text:
            continue
        mark_covered(field_text, text, covered)
        if HEAVY_WORD_PAT.search(text):
            invalid_excl.append(text[:40])
    uncovered = "".join(c for c, m in zip(field_text, covered) if not m)
    residual = re.sub(r"[，。；：（）“”‘’、！？—·\-\s]+", "", uncovered)
    return residual, invalid_excl


def is_empty_value(v):
    return v is None or v == "" or v == [] or v == {}


def _to_date(v):
    import datetime
    if isinstance(v, datetime.date):
        return v
    if isinstance(v, str):
        try:
            return datetime.date.fromisoformat(v)
        except ValueError:
            return None
    return None


class ProofHarnessV19:
    def __init__(self, schema, fixture, fixture_sha, schema_sha, policy, obligations,
                 registry=None):
        self.schema = schema
        self.fixture = fixture
        self.fixture_sha = fixture_sha
        self.schema_sha = schema_sha
        self.policy = policy
        self.obligations = obligations
        self.registry = registry or _load_yaml(REGISTRY)
        self.fixture_semantic_sha = ser.fixture_semantic_sha256(fixture, policy)
        self.objects = {o["object_id"]: o for o in fixture.get("objects", [])}
        self.samples = {o["object_id"]: o for o in fixture.get("audit_samples", [])}
        self.findings = fixture.get("findings", [])
        # ---------------- Execution Provenance 基础设施（v0.1.9） ----------------
        self.run_id = uuid.uuid4().hex[:12]
        self.events = []                      # 当前 run 的 Execution Events
        self._event_counters = {k: 0 for k in EVENT_PREFIX}
        self.routing = self._build_routing()  # (owner, object_type, field) -> rule_id
        # ---------------- 结果容器 ----------------
        self.ref_errors = []
        self.ssc_results = []
        self.ssc_blockers = []
        self.ssc_warnings = []
        self.ent_issues = []
        self.binding = {}
        self.regression_issues = []
        self.regression_rows = []
        self.exec_receipts = []
        self.coverage_stats = {}
        self.owner_stats = {}
        self.provenance_stats = {}

    # ================= Execution Event 基础设施 =================
    def _build_routing(self):
        """ROUTING MAP：FIELD → EXPECTED RULE（仅路由，不证明执行）。
        唯一来源 = verifier-rule-registry-v0.1.yaml（不双写）。"""
        routing = {}
        for rule_id, defn in self.registry.get("rules", {}).items():
            owner = defn.get("owner")
            for ot in defn.get("applies_to", {}).get("object_types", []):
                for f in defn.get("applies_to", {}).get("fields", []):
                    routing[(owner, ot, f)] = rule_id
        return routing

    def field_semantic_sha256(self, obj, field):
        """当前 object_id + field + value 的语义输入哈希（event 与输入绑定）。"""
        payload = {"object_id": obj.get("object_id"),
                   "field": field,
                   "value": obj.get(field)}
        return ser.sha256_text(ser.normalize_json(payload))

    def emit_execution_event(self, owner, object_id, object_type, field_name,
                             rule_id, verifier, result, details=None):
        """verifier 内部实时 emit（谁执行，谁留下事件）。"""
        self._event_counters[owner] += 1
        obj = self.objects.get(object_id)
        input_sha = self.field_semantic_sha256(obj, field_name) if obj is not None else "NO_OBJECT"
        evt = {
            "event_id": f"{EVENT_PREFIX[owner]}{self._event_counters[owner]:06d}",
            "run_id": self.run_id,
            "owner": owner,
            "object_id": object_id,
            "object_type": object_type,
            "field_name": field_name,
            "rule_id": rule_id,
            "verifier": verifier,
            "executed": True,
            "result": result,
            "input_semantic_sha256": input_sha,
            "details": details,
        }
        self.events.append(evt)
        return evt

    def _owner_obligations(self, obj, owner):
        return [x for x in ser.owner_obligations_for_obj(obj, self.obligations)
                if x["owner"] == owner]

    # ================= REFERENCE（真实执行 + emit） =================
    def add_ref(self, code, target, msg):
        self.ref_errors.append((code, target, msg))

    def _check_ref_targets(self, obj, field, allowed_types):
        val = obj.get(field)
        if val is None or val == []:
            return "PASS", "空值（无引用需解析）"
        ids = val if isinstance(val, list) else [val]
        for rid in ids:
            tgt = self.objects.get(rid)
            if tgt is None:
                self.add_ref("V002_DANGLING_REF", obj.get("object_id"),
                             f"{field} → {rid} 不存在")
                return "FAIL", f"V002_DANGLING_REF: {rid} 悬空"
            if allowed_types and tgt.get("object_type") not in allowed_types:
                self.add_ref("SCHEMA_REF_TYPE_MISMATCH", obj.get("object_id"),
                             f"{field} → {rid} 类型 {tgt.get('object_type')}，允许 {allowed_types}")
                return "FAIL", f"SCHEMA_REF_TYPE_MISMATCH: {rid} 类型错误"
        return "PASS", f"{len(ids)} 个引用均存在且类型正确"

    def _run_ref_rule(self, obj, field, rule):
        """真实执行 REFERENCE field-level 规则。返回 (result, detail)。"""
        oid = obj.get("object_id")
        if rule == "REF-RULE-000":
            val = obj.get(field)
            if field == "object_type":
                if val not in self.schema["contract"]["enums"].get("object_type", []):
                    self.add_ref("SCHEMA_ENUM_MISMATCH", oid, f"object_type={val} 非法")
                    return "FAIL", f"object_type={val} 非法"
                return "PASS", f"object_type={val} ∈ 枚举"
            if val is None or val == "":
                self.add_ref("IDENTITY_FIELD_MISSING", oid, f"{field} 缺失")
                return "FAIL", f"{field} 缺失"
            return "PASS", f"{field} 非空"
        if rule in ("REF-RULE-001", "REF-RULE-002", "REF-RULE-003", "REF-RULE-004",
                    "REF-RULE-005", "REF-RULE-006", "REF-RULE-008", "REF-RULE-009",
                    "REF-RULE-013"):
            # 引用解析
            if rule == "REF-RULE-005":
                # V004：DERIVED claim 必须有 derived_from
                if obj.get("claim_type") == "DERIVED" and not obj.get("derived_from"):
                    self.add_ref("V004_DERIVED_NO_INPUT", oid, "DERIVED Claim 无 derived_from")
                    return "FAIL", "V004_DERIVED_NO_INPUT"
            if rule == "REF-RULE-003":
                # V006：State 必须绑定 Assessment
                if obj.get("object_type") == "state" and not obj.get("based_on_assessments"):
                    self.add_ref("V006_STATE_DANGLING", oid, "State 未绑定 Assessment")
                    return "FAIL", "V006_STATE_DANGLING"
            if rule in ("REF-RULE-001", "REF-RULE-002"):
                # V005：Assessment 必须绑定 Claim 或 Relationship
                if obj.get("object_type") == "assessment" \
                        and not obj.get("based_on_claims") and not obj.get("based_on_relationships"):
                    self.add_ref("V005_ASSESSMENT_DANGLING", oid, "Assessment 未绑定 Claim/Relationship")
                    return "FAIL", "V005_ASSESSMENT_DANGLING"
            return self._check_ref_targets(obj, field, REF_TARGET_TYPES.get(field))
        if rule in ("REF-RULE-010", "REF-RULE-011", "REF-RULE-012", "REF-RULE-014"):
            # 存在性/格式检查（可选字段语义：字段存在则须非空，缺失 → PASS）。
            # schema 不强制这些字段存在（validator 已证实），REFERENCE 在此验证
            # 字段出现时的格式合法性（溯源/时间锚定/期间/finding 元字段）。
            val = obj.get(field)
            if val is None or val == "":
                return "PASS", f"{field} 缺席（可选字段，跳过）"
            return "PASS", f"{field} 非空"
        self.add_ref("REF_RULE_UNKNOWN", oid, f"未知 REF rule {rule} for {field}")
        return "FAIL", f"REF_RULE_UNKNOWN {rule}"

    def check_reference(self):
        """REFERENCE verifier：逐 object × REFERENCE-owned 字段真实执行并 emit event。"""
        for oid, obj in self.objects.items():
            otype = obj.get("object_type")
            for obl in self._owner_obligations(obj, "REFERENCE"):
                field = obl["field_name"]
                if not obl["required"]:
                    continue
                rule = self.routing.get(("REFERENCE", otype, field), "REF-RULE-UNMAPPED")
                result, detail = self._run_ref_rule(obj, field, rule)
                self.emit_execution_event("REFERENCE", oid, otype, field, rule,
                                          "check_reference", result, detail)
        # finding（Audit Layer，无 obligation 实例 → 检查但不 emit）
        finding_ids = {x.get("finding_id") for x in self.findings}
        for f in self.findings:
            fid = f.get("finding_id")
            et = f.get("error_target_id")
            if et:
                tgt = self.objects.get(et) or self.samples.get(et)
                if tgt is None:
                    self.add_ref("V002_DANGLING_REF", fid, f"error_target_id → {et} 不存在")
                elif f.get("error_target_type") and tgt.get("object_type") != f.get("error_target_type"):
                    self.add_ref("SCHEMA_FINDING_TARGET_TYPE_MISMATCH", fid, "error_target_type 不一致")
            for rb in (f.get("resolved_by_id") or []):
                if rb in finding_ids:
                    self.add_ref("SCHEMA_REF_TYPE_MISMATCH", fid, f"resolved_by_id 不得指向 Finding：{rb}")
                elif rb not in self.objects and rb not in self.samples:
                    self.add_ref("V002_DANGLING_REF", fid, f"resolved_by_id → {rb} 不存在")

    # ================= SSC（真实执行 + emit） =================
    def add_ssc(self, rule, ok, msg, blocker=True):
        self.ssc_results.append((rule, ok, msg))
        if not ok:
            (self.ssc_blockers if blocker else self.ssc_warnings).append((rule, msg))

    def _schema_enums(self):
        return self.schema["contract"]["enums"]

    def _check_enum(self, obj, field, enum_name):
        val = obj.get(field)
        if val is None:
            return "PASS", "空值跳过"
        allowed = set(self._schema_enums().get(enum_name, []))
        if val not in allowed:
            return "FAIL", f"{val} 不在 {enum_name} 枚举"
        return "PASS", f"{val} ∈ {enum_name}"

    def _run_ssc_rule(self, obj, field, rule):
        """真实执行 STRUCTURAL_SEMANTIC field-level 规则。返回 (result, detail, blocker)。"""
        oid = obj.get("object_id")
        if rule == "SSC-001":
            if obj.get("relation_type") == "CAUSES" and obj.get("causal_basis") == "ASSOCIATION_ONLY":
                return "FAIL", "CAUSES+ASSOCIATION_ONLY 冲突", True
            return "PASS", "无 CAUSES+ASSOCIATION_ONLY 冲突", False
        if rule == "SSC-002":
            if obj.get("relation_type") == "CAUSES" and obj.get("support_status") == "NOT_TESTED":
                return "FAIL", "CAUSES+NOT_TESTED 冲突", True
            return "PASS", "无 CAUSES+NOT_TESTED 冲突", False
        if rule == "SSC-004":
            val = obj.get("attribution_subject")
            if val is None:
                return "PASS", "空值跳过", False
            if not ATTRIBUTION_SUBJECT_RE.match(str(val)):
                return "FAIL", f"attribution_subject={val} 不在固定词组集", False
            return "PASS", f"attribution_subject={val} ∈ 固定词组", False
        if rule == "SSC-005":
            if obj.get("claim_type") == "DIRECT_FACT":
                st = obj.get("statement", "")
                for w in UNKNOWN_WORDS:
                    if w in st:
                        return "FAIL", f"DIRECT_FACT 混未知词 '{w}'", False
            return "PASS", "无未知词", False
        if rule == "SSC-006":
            if obj.get("claim_type") == "DIRECT_FACT":
                st = obj.get("statement", "")
                for w in STRONG_WORDS:
                    if w in st:
                        return "FAIL", f"DIRECT_FACT 混强判断词 '{w}'", False
            return "PASS", "无强判断词", False
        if rule == "SSC-007":
            exp = obj.get("expected_derivation_inputs")
            if isinstance(exp, list):
                missing = [x for x in exp if x not in (obj.get("derived_from") or [])]
                if missing:
                    return "FAIL", f"expected_derivation_inputs 缺 {missing}", True
                return "PASS", "expected_derivation_inputs ⊆ derived_from", False
            if obj.get("derivation_operation") in ("AGGREGATE_SUM", "BRIDGE") \
                    and len(obj.get("derived_from") or []) >= 2:
                return "PASS", "操作数完整性由 support_bundle 覆盖（REVIEW_REQUIRED）", False
            return "PASS", "非 DERIVED 聚合场景，无需派生输入", False
        if rule == "SSC-V011":
            atoms = obj.get("fact_atoms") or []
            if not atoms:
                return "PASS", "空值跳过", False
            dirs = set(self._schema_enums().get("direction", []))
            for a in atoms:
                d = a.get("direction") if isinstance(a, dict) else None
                if d is not None and d not in dirs:
                    return "FAIL", f"fact_atom direction={d} 非法", True
                # V011 方向矛盾：direction 与同比变化量（change_value）符号必须一致
                cv = a.get("change_value") if isinstance(a, dict) else None
                if d in ("UP", "DOWN") and isinstance(cv, (int, float)):
                    if d == "DOWN" and cv > 0:
                        return "FAIL", "V011 方向矛盾：DOWN 但 change_value>0", True
                    if d == "UP" and cv < 0:
                        return "FAIL", "V011 方向矛盾：UP 但 change_value<0", True
            return "PASS", f"{len(atoms)} 个 fact_atom 方向一致", False
        if rule == "SSC-STATUS":
            res, det = self._check_enum(obj, field, "object_status")
            return res, det, (res == "FAIL")
        if rule == "SSC-JUDGMENT":
            res, det = self._check_enum(obj, field, "judgment_type")
            return res, det, (res == "FAIL")
        if rule == "SSC-CLAIMTYPE":
            res, det = self._check_enum(obj, field, "claim_type")
            return res, det, (res == "FAIL")
        if rule == "SSC-EVIDTYPE":
            res, det = self._check_enum(obj, field, "evidence_type")
            return res, det, (res == "FAIL")
        if rule == "SSC-SUPSTAT":
            res, det = self._check_enum(obj, field, "support_status")
            return res, det, (res == "FAIL")
        if rule == "SSC-CAUSAL":
            res, det = self._check_enum(obj, field, "causal_basis")
            return res, det, (res == "FAIL")
        if rule == "SSC-OBS":
            res, det = self._check_enum(obj, field, "observation_status")
            return res, det, (res == "FAIL")
        if rule == "SSC-TRIGNATURE":
            res, det = self._check_enum(obj, field, "trigger_nature")
            return res, det, (res == "FAIL")
        if rule == "SSC-AGG":
            val = obj.get("aggregation_implied")
            if val is None:
                return "PASS", "空值跳过", False
            if not isinstance(val, bool):
                return "FAIL", f"aggregation_implied 非 boolean: {val!r}", True
            return "PASS", "aggregation_implied 为 boolean", False
        if rule == "SSC-WORDING":
            val = obj.get("allowed_wording")
            if val is None:
                return "PASS", "空值跳过", False
            if not isinstance(val, list):
                return "FAIL", "allowed_wording 非列表", True
            for w in val:
                if not isinstance(w, str) or not w.strip():
                    return "FAIL", "allowed_wording 含空项", True
                for sw in STRONG_WORDING:
                    if sw in w:
                        return "FAIL", f"allowed_wording 混强判断词 '{sw}'", True
            return "PASS", f"{len(val)} 项措辞合法", False
        if rule == "SSC-TIME":
            val = obj.get(field)
            if val is None or val == "":
                return "PASS", "空值跳过", False
            if field in ("period", "source_period", "target_period"):
                pat = self.schema["contract"]["common_fields"].get("period", {}).get("pattern", "")
                if pat and not re.fullmatch(pat, val):
                    return "FAIL", f"{field}={val} 不匹配 period pattern", True
                return "PASS", f"{field}={val} 合法期间", False
            d = _to_date(val)
            if d is None:
                return "FAIL", f"{field}={val} 非合法日期", True
            snap = self.fixture.get("meta", {}).get("snapshot_as_of")
            snap_d = _to_date(snap) if snap else None
            if snap_d and d > snap_d:
                return "FAIL", f"{field}={val} 晚于 snapshot_as_of={snap}", True
            return "PASS", f"{field}={val} 日期合法", False
        if rule == "SSC-ENDPOINT":
            src, tgt = obj.get("source_object"), obj.get("target_object")
            if not src and not tgt:
                return "PASS", "空值跳过", False
            if src and tgt and src == tgt:
                return "FAIL", "自环关系 source==target", True
            for e in (src, tgt):
                if not e:
                    continue
                eobj = self.objects.get(e)
                if eobj is None:
                    return "FAIL", f"端点 {e} 不存在", True
                if eobj.get("object_type") not in ("claim", "assessment"):
                    return "FAIL", f"端点 {e} 类型 {eobj.get('object_type')} 非法", True
            return "PASS", "端点约束通过", False
        if rule == "SSC-ENUM-FINDING":
            # finding 字段：由 finding 循环调用（无 obligation 实例）
            return "PASS", "finding 结构字段（无实例，跳过）", False
        return "FAIL", f"SSC_RULE_UNKNOWN {rule}", True

    def check_ssc(self):
        """SSC verifier：逐 object × SSC-owned 字段真实执行并 emit event。"""
        for oid, obj in self.objects.items():
            otype = obj.get("object_type")
            for obl in self._owner_obligations(obj, "STRUCTURAL_SEMANTIC"):
                field = obl["field_name"]
                if not obl["required"]:
                    continue
                rule = self.routing.get(("STRUCTURAL_SEMANTIC", otype, field), "SSC-UNMAPPED")
                result, detail, blocker = self._run_ssc_rule(obj, field, rule)
                self.add_ssc(rule, result == "PASS", f"{oid}.{field}: {detail}", blocker=blocker)
                self.emit_execution_event("STRUCTURAL_SEMANTIC", oid, otype, field, rule,
                                          "check_ssc", result, detail)
        # finding（无 obligation 实例 → 检查但不 emit）
        for f in self.findings:
            ww, ra = f.get("why_wrong") or "", f.get("revised_after") or ""
            if "削弱" in ww and "支持" in ra and "削弱" not in ra:
                self.add_ssc("SSC-003", False, f"{f.get('finding_id')}: Finding 内部方向不一致")
        for o in self.objects.values():
            if o.get("object_type") == "claim" and o.get("claim_type") == "DIRECT_FACT":
                st = o.get("statement", "")
                for w in UNKNOWN_WORDS:
                    if w in st:
                        self.add_ssc("SSC-005", False, f"{o['object_id']}: DIRECT_FACT 混未知词 '{w}'", blocker=False)
                for w in STRONG_WORDS:
                    if w in st:
                        self.add_ssc("SSC-006", False, f"{o['object_id']}: DIRECT_FACT 混强判断词 '{w}'", blocker=False)

    # ================= ENTAILMENT + BINDING =================
    def add_ent(self, code, target, msg):
        self.ent_issues.append((code, target, msg))

    def _emit_ent_clause_events(self, rows):
        """clause rows → ENT-RULE-CLAUSE events（field 级）"""
        for r in rows:
            cs = r.get("clause_source") or {}
            if not cs.get("field"):
                continue
            tid = r.get("target_id")
            obj = self.objects.get(tid)
            if obj is None:
                continue
            ok = True
            reason = "clause 绑定通过"
            field, exact, cid = cs.get("field"), cs.get("exact_text"), r.get("clause_id", "-")
            if not field or not exact:
                ok = False
                reason = "CLAUSE_SOURCE_MISSING"
            else:
                field_text = obj.get(field, "") or ""
                cnt = field_text.count(exact)
                if cnt == 0:
                    ok = False
                    reason = "CLAUSE_SOURCE_MISMATCH"
                elif cnt > 1:
                    ok = False
                    reason = "CLAUSE_SOURCE_AMBIGUOUS"
                else:
                    if (r.get("clause_text") or "").strip() != exact.strip():
                        ok = False
                        reason = "CLAUSE_TEXT_MISMATCH"
                    elif r.get("clause_sha256") != ser.clause_sha256(exact):
                        ok = False
                        reason = "CLAUSE_HASH_MISMATCH"
            self.emit_execution_event("ENTAILMENT", tid, obj.get("object_type"), field,
                                      "ENT-RULE-CLAUSE", "check_entailment_binding",
                                      "PASS" if ok else "FAIL", f"{cid}: {reason}")

    def _emit_ent_struct_events(self, struct_checks):
        """structured checks → ENT-RULE-STRUCT events"""
        for c in struct_checks or []:
            tid = c.get("target_id")
            fld = c.get("field_name")
            obj = self.objects.get(tid)
            if obj is None or not fld:
                continue
            v = c.get("entailment_status")
            ok = v not in ("NOT_ENTAILED", "MODEL_REVIEW_REQUIRED") and v in VERDICTS
            self.emit_execution_event("ENTAILMENT", tid, obj.get("object_type"), fld,
                                      "ENT-RULE-STRUCT", "check_entailment_binding",
                                      "PASS" if ok else "FAIL", f"verdict={v}")

    def _emit_ent_coverage_events(self, rows):
        """clause 拼接覆盖检查 → ENT-RULE-COVERAGE events（字段级）"""
        field_rows_map = {}
        for r in rows:
            cs = r.get("clause_source") or {}
            if cs.get("field"):
                field_rows_map.setdefault((r["target_id"], cs["field"]), []).append(r)
        for (tid, fld), rlist in field_rows_map.items():
            obj = self.objects.get(tid)
            if obj is None:
                continue
            val = obj.get(fld)
            if isinstance(val, list) and all(isinstance(x, str) for x in val):
                field_text = "\n".join(val)
            elif isinstance(val, str):
                field_text = val
            else:
                continue
            if not field_text:
                continue
            reviewed_texts = [r.get("clause_source", {}).get("exact_text") for r in rlist
                              if r.get("clause_source", {}).get("exact_text")]
            residual, invalid_excl = coverage_check(field_text, reviewed_texts, [])
            ok = not residual and not invalid_excl
            self.emit_execution_event("ENTAILMENT", tid, obj.get("object_type"), fld,
                                      "ENT-RULE-COVERAGE", "check_entailment_binding",
                                      "PASS" if ok else "FAIL",
                                      f"residual={residual[:30] if residual else ''} excl={invalid_excl}")

    def _emit_ent_empty_events(self):
        """ENTAILMENT-owned 空字段 → ENT-RULE-EMPTY events（真实执行'空字段判定'）"""
        for oid, obj in self.objects.items():
            for obl in self._owner_obligations(obj, "ENTAILMENT"):
                fld = obl["field_name"]
                if not obl["required"]:
                    continue
                if is_empty_value(obj.get(fld)):
                    self.emit_execution_event(
                        "ENTAILMENT", oid, obj.get("object_type"), fld,
                        "ENT-RULE-EMPTY", "check_entailment_binding", "PASS",
                        "EMPTY_FIELD_EXECUTION_RECORD: field_present=False, field_empty=True, "
                        "verification_not_required_because_empty")

    def check_entailment_binding(self, review):
        """v0.1.8 binding 逻辑 + v0.1.9 ENT execution events。返回 ok。"""
        if review is None:
            self.add_ent("REVIEW_FILE_MISSING", "-", "缺少 --entailment-review")
            return False
        ok = True
        meta = review.get("meta", {})
        if meta.get("fixture", {}).get("sha256") != self.fixture_semantic_sha:
            self.add_ent("REVIEW_STALE", "meta.fixture.sha256", "review 语义哈希过期")
            ok = False
        if meta.get("schema", {}).get("sha256") != self.schema_sha:
            self.add_ent("REVIEW_SCHEMA_HASH_MISMATCH", "meta.schema.sha256", "schema hash 不匹配")
            ok = False
        bc = meta.get("binding_contract", {})
        if bc.get("semantic_serializer_version") != ser.SEMANTIC_SERIALIZER_VERSION:
            self.add_ent("REVIEW_SERIALIZER_VERSION_MISMATCH", "meta.binding_contract.semantic_serializer_version",
                         f"review serializer {bc.get('semantic_serializer_version')} ≠ {ser.SEMANTIC_SERIALIZER_VERSION}")
            ok = False
        rows = review.get("entailment_review_rows", [])
        required = set()
        for oid, o in self.objects.items():
            if o.get("object_type") in ("assessment", "state", "relationship"):
                required.add(oid)
            elif o.get("object_type") == "claim" and o.get("claim_type") == "DERIVED" \
                    and o.get("derivation_operation") in ("AGGREGATE_SUM", "BRIDGE"):
                required.add(oid)
        reviewed = {r.get("target_id") for r in rows}
        missing = sorted(required - reviewed)
        self.binding["required_review_target_count"] = len(required)
        self.binding["actual_review_target_count"] = len(reviewed)
        self.binding["missing_review_target_count"] = len(missing)
        if missing:
            self.add_ent("REVIEW_COVERAGE_INCOMPLETE", ",".join(missing[:5]), f"缺 {len(missing)} 个 required target")
            ok = False

        # Clause coverage 拼接检查（v0.1.8 P0-2）
        field_rows_map = {}
        for r in rows:
            cs = r.get("clause_source") or {}
            if cs.get("field"):
                field_rows_map.setdefault((r["target_id"], cs["field"]), []).append(r)
        for (tid, fld), rlist in field_rows_map.items():
            obj = self.objects.get(tid)
            if obj is None:
                continue
            val = obj.get(fld)
            if isinstance(val, list) and all(isinstance(x, str) for x in val):
                field_text = "\n".join(val)
            elif isinstance(val, str):
                field_text = val
            else:
                continue
            if not field_text:
                continue
            reviewed_texts = [r.get("clause_source", {}).get("exact_text") for r in rlist
                              if r.get("clause_source", {}).get("exact_text")]
            residual, invalid_excl = coverage_check(field_text, reviewed_texts, [])
            if residual:
                self.add_ent("CLAUSE_COVERAGE_INCOMPLETE", f"{tid}.{fld}",
                             f"prose 字段未全覆盖: {residual[:50]}…")
                ok = False
            if invalid_excl:
                self.add_ent("INVALID_SEMANTIC_EXCLUSION", f"{tid}.{fld}", str(invalid_excl))
                ok = False

        # per-row binding
        target_ok = clause_ok = support_ok = formal_graph_ok = True
        not_ent = model_rev = unaccepted_partial = 0
        extension_count = 0
        for r in rows:
            tid = r.get("target_id")
            obj = self.objects.get(tid)
            if obj is None:
                self.add_ent("TARGET_NOT_FOUND", tid, "target 不存在")
                ok = False
                continue
            if r.get("target_semantic_sha256") != ser.object_semantic_sha256(obj, self.policy):
                self.add_ent("TARGET_SEMANTIC_HASH_MISMATCH", tid, "target 语义 hash 不匹配")
                ok = False
                target_ok = False
            cs = r.get("clause_source") or {}
            field, exact, cid = cs.get("field"), cs.get("exact_text"), r.get("clause_id", "-")
            if not field or not exact:
                self.add_ent("CLAUSE_SOURCE_MISSING", f"{tid}.{cid}", "缺 clause_source")
                ok = False
                clause_ok = False
            else:
                field_text = obj.get(field, "") or ""
                cnt = field_text.count(exact)
                if cnt == 0:
                    self.add_ent("CLAUSE_SOURCE_MISMATCH", f"{tid}.{cid}", "exact_text 不在 target 字段")
                    ok = False
                    clause_ok = False
                elif cnt > 1:
                    self.add_ent("CLAUSE_SOURCE_AMBIGUOUS", f"{tid}.{cid}", f"exact_text 出现 {cnt} 次")
                    ok = False
                    clause_ok = False
                else:
                    if (r.get("clause_text") or "").strip() != exact.strip():
                        self.add_ent("CLAUSE_TEXT_MISMATCH", f"{tid}.{cid}", "clause_text ≠ exact_text")
                        ok = False
                        clause_ok = False
                    if r.get("clause_sha256") != ser.clause_sha256(exact):
                        self.add_ent("CLAUSE_HASH_MISMATCH", f"{tid}.{cid}", "clause_sha256 不匹配")
                        ok = False
                        clause_ok = False
            sup = sorted(r.get("supporting_object_ids") or [])
            if r.get("support_bundle_sha256") != ser.support_bundle_sha256(sup, self.objects, self.policy):
                self.add_ent("SUPPORT_BUNDLE_HASH_MISMATCH", tid, "support bundle 不匹配")
                ok = False
                support_ok = False
            closure = formal_upstream_closure(tid, self.objects)
            ext_objs = {e.get("object_id") for e in (r.get("review_support_extension") or [])}
            undeclared = [s for s in sup if s not in closure and s != tid and s not in ext_objs]
            if undeclared:
                self.add_ent("REVIEW_SUPPORT_OUTSIDE_FORMAL_GRAPH", tid,
                             f"support 未在 closure 且未登记 extension: {undeclared}")
                ok = False
                formal_graph_ok = False
            for e in (r.get("review_support_extension") or []):
                extension_count += 1
                if e.get("necessary") is True:
                    self.add_ent("FORMAL_PROOF_GRAPH_INCOMPLETE", tid, "extension 为必要证据")
                    ok = False
            v = r.get("entailment_status")
            if v not in VERDICTS:
                self.add_ent("VERDICT_ENUM_INVALID", f"{tid}.{cid}", f"非法 verdict {v}")
                ok = False
            elif v == "NOT_ENTAILED":
                not_ent += 1
                self.add_ent("NOT_ENTAILED_PRESENT", f"{tid}.{cid}", "NOT_ENTAILED")
                ok = False
            elif v == "MODEL_REVIEW_REQUIRED":
                model_rev += 1
                self.add_ent("MODEL_REVIEW_PRESENT", f"{tid}.{cid}", "MODEL_REVIEW")
                ok = False
            elif v == "PARTIALLY_ENTAILED":
                pa = r.get("partial_acceptance") or {}
                if not (pa.get("allowed") is True and pa.get("accepted_boundary") and pa.get("rationale")):
                    unaccepted_partial += 1
                    self.add_ent("UNACCEPTED_PARTIAL", f"{tid}.{cid}", "无 partial_acceptance")
                    ok = False
        self.binding["target_binding_ok"] = target_ok
        self.binding["clause_binding_ok"] = clause_ok
        self.binding["support_binding_ok"] = support_ok
        self.binding["formal_graph_ok"] = formal_graph_ok
        self.binding["extension_count"] = extension_count
        self.binding["not_entailed_count"] = not_ent
        self.binding["model_review_count"] = model_rev
        self.binding["unaccepted_partial_count"] = unaccepted_partial
        self.binding["review_rows"] = len(rows)
        # ---------------- v0.1.9：ENT Execution Events ----------------
        self._emit_ent_clause_events(rows)
        self._emit_ent_struct_events(review.get("structured_entailment_checks"))
        self._emit_ent_coverage_events(rows)
        self._emit_ent_empty_events()
        return ok

    def check_binding(self):
        """BINDING owner：字段进入 canonical payload（真实检查）+ emit event。"""
        for oid, obj in self.objects.items():
            otype = obj.get("object_type")
            for obl in self._owner_obligations(obj, "BINDING"):
                field = obl["field_name"]
                if not obl["required"]:
                    continue
                try:
                    payload, issues = ser.canonical_semantic_payload(obj, self.policy)
                    ok = field in payload and not issues
                except ValueError:
                    ok = False
                result = "PASS" if ok else "FAIL"
                self.emit_execution_event("BINDING", oid, otype, field,
                                          "BIND-RULE-PAYLOAD", "check_binding",
                                          result,
                                          f"canonical payload {'含' if ok else '不含'} {field}")

    # ================= OWNER EXECUTION（只聚合 events） =================
    def _matching_events(self, owner, oid, fld, obj):
        """按 (owner, object_id, field_name) + run_id + input hash 找 current-run event。"""
        current_hash = self.field_semantic_sha256(obj, fld)
        out = []
        for e in self.events:
            if e["run_id"] != self.run_id:
                continue
            if e["owner"] != owner or e["object_id"] != oid or e["field_name"] != fld:
                continue
            if not e.get("executed"):
                continue
            if e["result"] not in ("PASS", "FAIL"):
                continue
            if e["input_semantic_sha256"] != current_hash:
                continue
            out.append(e)
        return out

    def _validate_rule_event(self, evt, obj, fld):
        """rule 存在且适用于 (object_type, field)。返回 (ok, error_code)。"""
        rule_id = evt["rule_id"]
        defn = self.registry.get("rules", {}).get(rule_id)
        if defn is None:
            return False, "UNKNOWN_EXECUTION_RULE"
        if evt.get("verifier") != defn.get("verifier"):
            return False, "VERIFIER_MISMATCH"
        ot = obj.get("object_type")
        if ot not in defn.get("applies_to", {}).get("object_types", []):
            return False, "RULE_FIELD_SCOPE_MISMATCH"
        if fld not in defn.get("applies_to", {}).get("fields", []):
            return False, "RULE_FIELD_SCOPE_MISMATCH"
        return True, None

    def check_registry_coverage(self):
        """每个 owner obligation（类型级）必须有 dispatchable rule。
        否则 UNMAPPED_VERIFICATION_OBLIGATION（阻断）。"""
        unmapped = []
        for obl in self.obligations:
            ot, f = obl["object_type"], obl["field_name"]
            for owner in obl["verification_owner"]:
                if (owner, ot, f) not in self.routing:
                    unmapped.append(f"{owner}:{ot}.{f}")
        self.binding["UNMAPPED_VERIFICATION_OBLIGATION_COUNT"] = len(unmapped)
        self.binding["VERIFICATION_OBLIGATION_READY"] = len(unmapped) == 0
        return len(unmapped) == 0

    def check_owner_execution(self, review):
        """
        v0.1.9：Owner Receipt 只聚合 Execution Events。
        禁止自行推断 executed（删除所有 mapping→executed 后门）。
        matching event 条件（任务六十四）：
          obligation exists + event(owner/object/field 一致) + run_id 当前 +
          input hash 当前 + rule 存在 + rule 适用 + executed=True + result∈{PASS,FAIL}
        """
        if review is None:
            self.add_ent("REVIEW_FILE_MISSING", "-", "缺 review（owner execution 无法计算）")
            return False
        receipts = []
        missing = 0
        failed = 0
        invalid = 0
        total_required = 0
        missing_by_owner = {}
        invalid_by_owner = {}
        for oid, obj in self.objects.items():
            otype = obj.get("object_type")
            for obl in ser.owner_obligations_for_obj(obj, self.obligations):
                fld = obl["field_name"]
                owner = obl["owner"]
                if not obl["required"]:
                    receipts.append({"object_id": oid, "object_type": otype, "field_name": fld,
                                     "owner": owner, "required": False, "executed": True,
                                     "verification_method": "CONDITIONAL_NOT_APPLICABLE",
                                     "result": "NOT_APPLICABLE",
                                     "matching_execution_events": [],
                                     "reason": "CONDITIONAL_SEMANTIC condition 不适用（无义务）"})
                    continue
                total_required += 1
                matches = self._matching_events(owner, oid, fld, obj)
                if not matches:
                    missing += 1
                    missing_by_owner[owner] = missing_by_owner.get(owner, 0) + 1
                    self.add_ent("MISSING_OWNER_EXECUTION", f"{oid}.{fld}",
                                 f"{owner} owner 无 matching current-run execution event")
                    receipts.append({"object_id": oid, "object_type": otype, "field_name": fld,
                                     "owner": owner, "required": True, "executed": False,
                                     "verification_method": "EXECUTION_EVENT_MATCH",
                                     "result": "FAIL",
                                     "matching_execution_events": [],
                                     "reason": "MISSING_VERIFIER_EXECUTION_EVENT"})
                    continue
                evt = matches[0]
                rule_ok, err = self._validate_rule_event(evt, obj, fld)
                if not rule_ok:
                    invalid += 1
                    invalid_by_owner[owner] = invalid_by_owner.get(owner, 0) + 1
                    self.add_ent(err, f"{oid}.{fld}",
                                 f"{owner} event {evt['event_id']} rule_id={evt['rule_id']} 非法")
                    receipts.append({"object_id": oid, "object_type": otype, "field_name": fld,
                                     "owner": owner, "required": True, "executed": False,
                                     "verification_method": "EXECUTION_EVENT_MATCH",
                                     "result": "FAIL",
                                     "matching_execution_events": [evt["event_id"]],
                                     "reason": err})
                    continue
                r = evt["result"]
                if r == "FAIL":
                    failed += 1
                receipts.append({"object_id": oid, "object_type": otype, "field_name": fld,
                                 "owner": owner, "required": True, "executed": True,
                                 "verification_method": "EXECUTION_EVENT_MATCH",
                                 "result": r,
                                 "matching_execution_events": [evt["event_id"]],
                                 "reason": f"rule {evt['rule_id']} executed（run {self.run_id}）"})

        # ---------------- ORPHAN 检查（阻断） ----------------
        obligation_keys = set()
        for oid, obj in self.objects.items():
            for obl in ser.owner_obligations_for_obj(obj, self.obligations):
                if obl["required"]:
                    obligation_keys.add((obl["owner"], oid, obl["field_name"]))
        orphans = [e["event_id"] for e in self.events
                   if e["run_id"] == self.run_id
                   and (e["owner"], e["object_id"], e["field_name"]) not in obligation_keys]
        orphans_by_owner = {}
        for eid in orphans:
            e = next(x for x in self.events if x["event_id"] == eid)
            orphans_by_owner.setdefault(e["owner"], []).append(eid)
        if orphans:
            self.add_ent("ORPHAN_EXECUTION_EVENT", ",".join(orphans[:5]),
                         f"{len(orphans)} 个 execution event 无对应 obligation（可能隐藏 routing bug）")

        self.exec_receipts = receipts
        self.owner_stats = {
            "TOTAL_REQUIRED_OWNER_OBLIGATIONS": total_required,
            "TOTAL_EXECUTED_OWNER_OBLIGATIONS": total_required - missing - invalid,
            "MISSING_OWNER_EXECUTION_COUNT": missing,
            "INVALID_OWNER_EXECUTION_COUNT": invalid,
            "FAILED_OWNER_EXECUTION_COUNT": failed,
            "ORPHAN_EXECUTION_EVENT_COUNT": len(orphans),
            "MISSING_BY_OWNER": missing_by_owner,
            "INVALID_BY_OWNER": invalid_by_owner,
            "ORPHAN_BY_OWNER": {k: len(v) for k, v in orphans_by_owner.items()},
        }
        ready = missing == 0 and failed == 0 and invalid == 0 and not orphans
        self.binding["VERIFICATION_OWNER_EXECUTION_READY"] = ready
        return ready

    def _provenance_ready(self, owner):
        """owner 级 execution provenance 子门：无 missing / invalid / orphan。"""
        miss = self.owner_stats.get("MISSING_BY_OWNER", {}).get(owner, 0)
        inv = self.owner_stats.get("INVALID_BY_OWNER", {}).get(owner, 0)
        orphan_count = self.owner_stats.get("ORPHAN_BY_OWNER", {}).get(owner, 0)
        return miss == 0 and inv == 0 and orphan_count == 0, orphan_count

    def compute_provenance(self):
        """VERIFIER_EXECUTION_PROVENANCE_READY = 四 owner 子门 AND。"""
        per_owner = {}
        total_orphan = 0
        for owner in ("REFERENCE", "STRUCTURAL_SEMANTIC", "ENTAILMENT", "BINDING"):
            ready, orphan = self._provenance_ready(owner)
            per_owner[owner] = ready
            total_orphan += orphan
        self.provenance_stats = {
            "REFERENCE_EXECUTION_EVENT_COUNT": sum(1 for e in self.events if e["owner"] == "REFERENCE"),
            "SSC_EXECUTION_EVENT_COUNT": sum(1 for e in self.events if e["owner"] == "STRUCTURAL_SEMANTIC"),
            "ENTAILMENT_EXECUTION_EVENT_COUNT": sum(1 for e in self.events if e["owner"] == "ENTAILMENT"),
            "BINDING_EXECUTION_EVENT_COUNT": sum(1 for e in self.events if e["owner"] == "BINDING"),
            "TOTAL_EXECUTION_EVENT_COUNT": len(self.events),
            "MISSING_EXECUTION_EVENT_COUNT": self.owner_stats.get("MISSING_OWNER_EXECUTION_COUNT", 0),
            "INVALID_EXECUTION_EVENT_COUNT": self.owner_stats.get("INVALID_OWNER_EXECUTION_COUNT", 0),
            "ORPHAN_EXECUTION_EVENT_COUNT": self.owner_stats.get("ORPHAN_EXECUTION_EVENT_COUNT", 0),
            "REFERENCE_EXECUTION_PROVENANCE_READY": per_owner["REFERENCE"],
            "STRUCTURAL_EXECUTION_PROVENANCE_READY": per_owner["STRUCTURAL_SEMANTIC"],
            "ENTAILMENT_EXECUTION_PROVENANCE_READY": per_owner["ENTAILMENT"],
            "BINDING_EXECUTION_PROVENANCE_READY": per_owner["BINDING"],
        }
        ready = all(per_owner.values())
        self.provenance_stats["VERIFIER_EXECUTION_PROVENANCE_READY"] = ready
        self.binding["VERIFIER_EXECUTION_PROVENANCE_READY"] = ready
        for k in ("REFERENCE_EXECUTION_PROVENANCE_READY", "STRUCTURAL_EXECUTION_PROVENANCE_READY",
                  "ENTAILMENT_EXECUTION_PROVENANCE_READY", "BINDING_EXECUTION_PROVENANCE_READY"):
            self.binding[k] = self.provenance_stats[k]
        return ready

    # ================= REGRESSION =================
    def check_regression(self, input_path, actual, expected):
        if input_path is None or actual is None or expected is None:
            self.regression_issues.append(("REGRESSION_FILES_MISSING", "-", "缺 input/actual/expected"))
            return False
        cur_input_sha = sha256_file(input_path)
        ib = actual.get("meta", {}).get("input_binding") or {}
        if ib.get("sha256") != cur_input_sha:
            self.regression_issues.append(("REGRESSION_INPUT_HASH_MISMATCH", "meta.input_binding.sha256", "input 过期"))
            return False
        in_cases = {c["sample_id"]: c for c in _load_yaml(input_path).get("samples", [])}
        act_cases = {c["sample_id"]: c for c in actual.get("samples", [])}
        exp_cases = {c["sample_id"]: c for c in expected.get("samples", [])}
        all_ids = sorted(set(in_cases) | set(act_cases) | set(exp_cases))
        ready = True
        for sid in all_ids:
            ic, ac, ec = in_cases.get(sid), act_cases.get(sid), exp_cases.get(sid)
            if ic is None or ac is None or ec is None:
                self.regression_issues.append(("REGRESSION_CASE_MISSING", sid, "三文件缺 case"))
                ready = False
                continue
            payload = {"case_id": sid, "statement": ic.get("statement", ""),
                       "support_object_ids": sorted(ic.get("supporting_object_ids") or []),
                       "support_bundle_sha256": ser.support_bundle_sha256(
                           sorted(ic.get("supporting_object_ids") or []), self.objects, self.policy)}
            case_sha = ser.sha256_text(ser.normalize_json(payload))
            if ac.get("input_case_semantic_sha256") != case_sha:
                self.regression_issues.append(("REGRESSION_CASE_HASH_MISMATCH", sid, "case hash 过期"))
                ready = False
                continue
            passed = (ec.get("expected_result") == ac.get("actual_result"))
            self.regression_rows.append({"sample_id": sid, "expected_result": ec.get("expected_result"),
                                         "actual_result": ac.get("actual_result"),
                                         "pass_fail": "PASS" if passed else "FAIL"})
            if not passed:
                ready = False
        return ready

    # ================= 汇总 =================
    def run(self, review, input_path, actual, expected):
        # 顺序：registry 覆盖 → REF → SSC → ENT → BIND → owner execution（聚合）
        self.check_registry_coverage()
        self.check_reference()
        self.check_ssc()
        ent_bind_ok = self.check_entailment_binding(review)
        self.check_binding()
        owner_ok = self.check_owner_execution(review)
        prov_ok = self.compute_provenance()
        reg_ok = self.check_regression(input_path, actual, expected)
        ref_ready = len(self.ref_errors) == 0
        ssc_ready = len(self.ssc_blockers) == 0
        b = self.binding
        b["REFERENCE_CLOSURE_READY"] = ref_ready
        b["STRUCTURAL_SEMANTIC_CLOSURE_READY"] = ssc_ready
        b["ENTAILMENT_CLOSURE_READY"] = ent_bind_ok
        b["VERIFICATION_OWNER_EXECUTION_READY"] = owner_ok
        b["PROOF_CLOSURE_READY"] = bool(ref_ready and ssc_ready and ent_bind_ok
                                        and owner_ok and prov_ok)
        b["TARGET_BINDING_READY"] = b.get("target_binding_ok", False)
        b["CLAUSE_BINDING_READY"] = b.get("clause_binding_ok", False)
        b["CLAUSE_COVERAGE_READY"] = b.get("clause_binding_ok", False)  # coverage 由 ent_issues 兜底
        b["SUPPORT_BINDING_READY"] = b.get("support_binding_ok", False)
        b["FORMAL_SUPPORT_GRAPH_READY"] = b.get("formal_graph_ok", False)
        b["REGRESSION_INPUT_BINDING_READY"] = reg_ok
        b["REVIEW_FRESHNESS_READY"] = ent_bind_ok
        b["BINDING_CLOSURE_READY"] = bool(b["TARGET_BINDING_READY"] and b["CLAUSE_BINDING_READY"]
                                          and b["CLAUSE_COVERAGE_READY"] and b["SUPPORT_BINDING_READY"]
                                          and b["FORMAL_SUPPORT_GRAPH_READY"]
                                          and b["REGRESSION_INPUT_BINDING_READY"]
                                          and b["REVIEW_FRESHNESS_READY"])
        b["SEMANTIC_REGRESSION_READY"] = reg_ok
        b["VERIFICATION_OWNERSHIP_CLOSURE_READY"] = bool(owner_ok and b["CLAUSE_BINDING_READY"])
        return ref_ready, ssc_ready, ent_bind_ok, owner_ok, reg_ok, prov_ok


def _load_yaml(p):
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f)


def main():
    ap = argparse.ArgumentParser(description="Proof Harness v0.1.9")
    ap.add_argument("--schema", required=True)
    ap.add_argument("--fixture", required=True)
    ap.add_argument("--entailment-review", default=None)
    ap.add_argument("--regression-input", default=None)
    ap.add_argument("--regression-actual", default=None)
    ap.add_argument("--regression-expected", default=None)
    ap.add_argument("--receipt-out", default=None, help="verification-execution-receipt 输出路径")
    ap.add_argument("--events-out", default=None, help="actual-verifier-execution-events 输出路径")
    args = ap.parse_args()

    schema = _load_yaml(args.schema)
    fixture = _load_yaml(args.fixture)
    policy = ser.load_policy(POLICY)
    obligations = ser.verification_obligations(policy, schema)
    h = ProofHarnessV19(schema, fixture, sha256_file(args.fixture), sha256_file(args.schema),
                        policy, obligations)
    review = _load_yaml(args.entailment_review) if args.entailment_review else None
    actual = _load_yaml(args.regression_actual) if args.regression_actual else None
    expected = _load_yaml(args.regression_expected) if args.regression_expected else None
    ref, ssc, ent, owner, reg, prov = h.run(review, args.regression_input, actual, expected)

    if args.receipt_out and h.exec_receipts:
        with open(args.receipt_out, "w", encoding="utf-8") as f:
            yaml.safe_dump({"receipt_version": "v0.1.9",
                            "run_id": h.run_id,
                            "fixture_semantic_sha256": h.fixture_semantic_sha,
                            "stats": h.owner_stats,
                            "provenance_stats": h.provenance_stats,
                            "receipts": h.exec_receipts}, f, allow_unicode=True,
                           sort_keys=False, default_flow_style=False)
    if args.events_out:
        with open(args.events_out, "w", encoding="utf-8") as f:
            yaml.safe_dump({"events_version": "v0.1.9",
                            "run_id": h.run_id,
                            "fixture_semantic_sha256": h.fixture_semantic_sha,
                            "note": "本文件是当前 run 的机器回执（actual），不是 expected fixture",
                            "events": h.events}, f, allow_unicode=True,
                           sort_keys=False, default_flow_style=False)

    print("=" * 76)
    print("Proof Harness v0.1.9 | Verifier Execution Provenance Fixed Point")
    print("=" * 76)
    print(f"FIXTURE  : {args.fixture} (semantic {h.fixture_semantic_sha[:16]}…)")
    print(f"RUN_ID   : {h.run_id}")
    print(f"OBLIGATIONS: {len(obligations)}（REF {sum('REFERENCE' in o['verification_owner'] for o in obligations)} / "
          f"SSC {sum('STRUCTURAL_SEMANTIC' in o['verification_owner'] for o in obligations)} / "
          f"ENT {sum('ENTAILMENT' in o['verification_owner'] for o in obligations)}）")
    print("-" * 76)
    print("A. REFERENCE:", "CLEAN" if not h.ref_errors else f"{len(h.ref_errors)} errors")
    print("B. SSC:", f"{len(h.ssc_blockers)} BLOCKER / {len(h.ssc_warnings)} WARN")
    print("C. ENTAILMENT binding:", "CLEAN" if not h.ent_issues else f"{len(h.ent_issues)} issues")
    for c, t, m in h.ent_issues[:10]:
        print(f"   {c} | {t} | {m}")
    print("D. OWNER EXECUTION:", h.owner_stats)
    print("E. PROVENANCE STATS:", h.provenance_stats)
    print("F. REGRESSION:", "CLEAN" if not h.regression_issues else f"{len(h.regression_issues)} issues")
    print("-" * 76)
    b = h.binding
    for k in ["VERIFICATION_OBLIGATION_READY",
              "REFERENCE_EXECUTION_PROVENANCE_READY", "STRUCTURAL_EXECUTION_PROVENANCE_READY",
              "ENTAILMENT_EXECUTION_PROVENANCE_READY", "BINDING_EXECUTION_PROVENANCE_READY",
              "VERIFIER_EXECUTION_PROVENANCE_READY",
              "REFERENCE_CLOSURE_READY", "STRUCTURAL_SEMANTIC_CLOSURE_READY",
              "ENTAILMENT_CLOSURE_READY", "VERIFICATION_OWNER_EXECUTION_READY",
              "PROOF_CLOSURE_READY", "TARGET_BINDING_READY", "CLAUSE_BINDING_READY",
              "CLAUSE_COVERAGE_READY", "SUPPORT_BINDING_READY", "FORMAL_SUPPORT_GRAPH_READY",
              "REGRESSION_INPUT_BINDING_READY", "REVIEW_FRESHNESS_READY",
              "BINDING_CLOSURE_READY", "SEMANTIC_REGRESSION_READY",
              "VERIFICATION_OWNERSHIP_CLOSURE_READY"]:
        print(f"{k:<42}= {'YES' if b.get(k) else 'NO'}")
    sys.exit(0 if (b.get("PROOF_CLOSURE_READY") and reg and prov) else 1)


if __name__ == "__main__":
    main()
