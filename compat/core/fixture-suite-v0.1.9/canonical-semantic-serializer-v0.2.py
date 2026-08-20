# -*- coding: utf-8 -*-
"""
Canonical Semantic Serializer v0.2 —— Semantic Field Policy 驱动
================================================================
v0.1 问题（HF-V017-001）：手工字段列表（FIELDS_BY_TYPE）漏掉 object_status/
judgment_type/core_unknowns/key_triggers/decision_impact/allowed_wording/
importance/priority/observation_status 等 Schema 字段 → 形成"第二套 Schema"。

v0.2 原则（任务六/十三/十四）：
  1. 字段全集来自 Frozen Schema v0.1.2（机器枚举），不是手工列表；
  2. 分类来自 semantic-field-policy-v0.1.yaml（SEMANTIC / NON_SEMANTIC /
     CONDITIONAL_SEMANTIC），禁止 UNCLASSIFIED；
  3. canonical_semantic_payload(obj, policy) 逐字段按 policy 分类：
     - SEMANTIC → 进入 payload
     - CONDITIONAL_SEMANTIC → 满足 condition 进入
     - NON_SEMANTIC → 排除
     - 未分类/未知字段 → SEMANTIC_FIELD_UNCLASSIFIED（不得静默忽略）
  4. 语义字段必须登记 verification_owner（semantic-surface-coverage-tests 校验）。
"""
import datetime
import hashlib
import json
import re

SEMANTIC_SERIALIZER_VERSION = "v0.2"

# ---------------------------------------------------------------------------
# JSON 归一化（与 v0.1 一致）
# ---------------------------------------------------------------------------
def _jsonable(v):
    if isinstance(v, (datetime.date, datetime.datetime)):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return v


def normalize_json(obj):
    return json.dumps(_jsonable(obj), ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def sha256_text(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Policy 加载与查询
# ---------------------------------------------------------------------------
def load_policy(path):
    import yaml
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _eval_condition(cond, obj):
    """评估 CONDITIONAL_SEMANTIC 的 condition（安全命名空间）。无法评估时保守视为生效。"""
    if not cond:
        return True
    try:
        ns = {k: v for k, v in obj.items() if isinstance(v, (str, int, float, bool, list))}
        return bool(eval(cond, {"__builtins__": {}}, ns))  # noqa: S307
    except Exception:
        return True


def field_spec(policy, otype, field):
    """返回 (class, condition, owners) 或 None。先查对象类型专属，再查 common。"""
    fc = policy.get("field_classification", {})
    for section in (fc.get(otype, {}), fc.get("common", {})):
        if field in section:
            sp = section[field]
            return sp.get("class"), sp.get("condition"), sp.get("verification_owner", [])
    return None


# ---------------------------------------------------------------------------
# 核心 API（policy 驱动）
# ---------------------------------------------------------------------------
def canonical_semantic_payload(obj, policy):
    """
    返回 (payload, issues)。issues 非空（含 SEMANTIC_FIELD_UNCLASSIFIED）时
    调用方必须 FAIL——禁止 serializer 静默忽略任何 Schema 合法字段。
    """
    otype = obj.get("object_type")
    payload = {}
    issues = []
    for key, val in obj.items():
        if val is None:
            continue
        spec = field_spec(policy, otype, key)
        if spec is None:
            issues.append(("SEMANTIC_FIELD_UNCLASSIFIED", key,
                           f"对象 {obj.get('object_id')} 字段 {key} 未在 policy 中分类"))
            continue
        cls, cond, _ = spec
        if cls == "SEMANTIC":
            payload[key] = val
        elif cls == "CONDITIONAL_SEMANTIC":
            if _eval_condition(cond, obj):
                payload[key] = val
        elif cls == "NON_SEMANTIC":
            continue
        else:
            issues.append(("SEMANTIC_FIELD_UNCLASSIFIED", key,
                           f"非法分类 {cls}（policy）"))
    # object_id/object_type 保底（即使 policy 异常也保留身份）
    for k in ("object_id", "object_type"):
        if k not in payload and k in obj:
            payload[k] = obj[k]
    return payload, issues


def object_semantic_sha256(obj, policy):
    payload, issues = canonical_semantic_payload(obj, policy)
    if issues:
        raise ValueError(f"serializer 拒绝含未分类字段的对象：{issues[:3]}")
    return sha256_text(normalize_json(payload))


def clause_sha256(clause_text):
    return sha256_text((clause_text or "").strip())


def support_bundle_sha256(support_ids, objs, policy):
    entries = []
    for sid in sorted(set(support_ids)):
        o = objs.get(sid)
        if o is None:
            entries.append({"object_id": sid, "semantic_sha256": "MISSING"})
        else:
            entries.append({"object_id": sid,
                            "semantic_sha256": object_semantic_sha256(o, policy)})
    return sha256_text(normalize_json({"bundle": entries}))


META_SEMANTIC_FIELDS = ["ir_schema_version", "ir_spec_version", "company",
                        "snapshot_as_of", "subject", "canonical_truth_version"]


def fixture_semantic_sha256(fixture, policy):
    """
    Fixture 语义聚合哈希：全部对象 canonical payload + meta 语义字段。
    语义变化（含 object_status/core_unknowns 等）→ 变化；无关 metadata → 稳定。
    """
    objects = []
    for o in fixture.get("objects", []):
        payload, issues = canonical_semantic_payload(o, policy)
        if issues:
            raise ValueError(f"fixture 语义聚合失败：{issues[:2]}")
        objects.append(payload)
    objects.sort(key=lambda p: p.get("object_id") or "")
    meta = fixture.get("meta", {}) or {}
    meta_payload = {k: meta[k] for k in META_SEMANTIC_FIELDS if k in meta}
    return sha256_text(normalize_json({"meta": meta_payload, "objects": objects}))


# ---------------------------------------------------------------------------
# Schema / Policy 覆盖统计（任务十五）
# ---------------------------------------------------------------------------
def schema_field_inventory(schema):
    """机器枚举 Schema 字段全集：{otype: [field,...]}（含 common 并入各类型）。"""
    contract = schema.get("contract", {})
    common = set(contract.get("common_fields", {}).keys())
    inv = {}
    for otype, otdef in contract.get("object_types", {}).items():
        fields = set(otdef.get("fields", {}).keys()) | common
        inv[otype] = sorted(fields)
    inv["meta"] = sorted(contract.get("meta_contract", {}).keys())
    return inv


def policy_coverage_stats(policy, schema):
    """返回覆盖统计（任务十五）。UNCLASSIFIED=0 且 UNKNOWN=0 才 READY。"""
    inv = schema_field_inventory(schema)
    fc = policy.get("field_classification", {})
    schema_count = 0
    unclassified = []
    unknown_policy = []
    for otype, fields in inv.items():
        for f in fields:
            schema_count += 1
            in_otype = f in fc.get(otype, {})
            in_common = f in fc.get("common", {})
            if otype == "meta":
                in_common = False
            if not in_otype and not in_common:
                unclassified.append(f"{otype}.{f}")
    # policy 中声明的字段是否 schema 存在（UNKNOWN_POLICY_FIELD）
    obj_types = [t for t in inv if t != "meta"]
    for otype, sec in fc.items():
        for f in sec:
            if otype == "common":
                # common 字段已并入每个对象类型的 inventory
                known = any(f in inv.get(t, []) for t in obj_types)
            else:
                known = f in inv.get(otype, [])
            if not known:
                unknown_policy.append(f"{otype}.{f}")
    return {
        "SCHEMA_FIELD_COUNT": schema_count,
        "POLICY_CLASSIFIED_FIELD_COUNT": schema_count - len(unclassified),
        "UNCLASSIFIED_FIELD_COUNT": len(unclassified),
        "UNCLASSIFIED_FIELDS": unclassified,
        "UNKNOWN_POLICY_FIELD_COUNT": len(unknown_policy),
        "UNKNOWN_POLICY_FIELDS": unknown_policy,
    }


def semantic_fields_without_owner(policy, schema):
    """返回无 verification_owner 的 SEMANTIC/CONDITIONAL_SEMANTIC 字段清单。"""
    inv = schema_field_inventory(schema)
    fc = policy.get("field_classification", {})
    no_owner = []
    for otype, fields in inv.items():
        for f in fields:
            sp = fc.get(otype, {}).get(f) or fc.get("common", {}).get(f)
            if sp is None:
                continue
            if sp.get("class") in ("SEMANTIC", "CONDITIONAL_SEMANTIC") \
                    and not sp.get("verification_owner"):
                no_owner.append(f"{otype}.{f}")
    return no_owner


# ---------------------------------------------------------------------------
# Verification Obligation 机器派生（v0.1.8 新增，任务七/八）
# ---------------------------------------------------------------------------
def _condition_applies(cond, obj):
    """CONDITIONAL_SEMANTIC 的 condition 计算：True=applies。无法评估时保守视为生效。"""
    if not cond:
        return True
    try:
        ns = {k: v for k, v in obj.items() if isinstance(v, (str, int, float, bool, list))}
        return bool(eval(cond, {"__builtins__": {}}, ns))  # noqa: S307
    except Exception:
        return True


def verification_obligations(policy, schema):
    """
    字段级 Verification Obligation（机器派生，禁手填）：
    每个 object_type 的每个字段，若 semantic_class in (SEMANTIC, CONDITIONAL_SEMANTIC)
    且 verification_owner 非空 → 一条 obligation。
    返回 [{object_type, field_name, semantic_class, verification_owner, condition}]。
    """
    inv = schema_field_inventory(schema)
    fc = policy.get("field_classification", {})
    obligations = []
    for otype, fields in inv.items():
        if otype == "meta":
            continue
        for f in fields:
            sp = fc.get(otype, {}).get(f) or fc.get("common", {}).get(f)
            if sp is None:
                continue
            if sp.get("class") in ("SEMANTIC", "CONDITIONAL_SEMANTIC") \
                    and sp.get("verification_owner"):
                obligations.append({
                    "object_type": otype,
                    "field_name": f,
                    "semantic_class": sp.get("class"),
                    "verification_owner": list(sp.get("verification_owner", [])),
                    "condition": sp.get("condition"),
                })
    return obligations


def owner_obligations_for_obj(obj, obligations):
    """对象实例级 owner obligations：过滤类型 + CONDITIONAL 计算 applies。"""
    otype = obj.get("object_type")
    out = []
    for obl in obligations:
        if obl["object_type"] != otype:
            continue
        applies = True
        if obl["semantic_class"] == "CONDITIONAL_SEMANTIC":
            applies = _condition_applies(obl.get("condition"), obj)
        for owner in obl["verification_owner"]:
            out.append({
                "field_name": obl["field_name"],
                "owner": owner,
                "semantic_class": obl["semantic_class"],
                "condition_applies": applies,
                "required": applies,
            })
    return out


def required_entailment_fields(obj, obligations):
    """
    required entailment fields（任务十六，Policy 派生，不写死 REVIEWABLE_FIELDS）：
    该对象所有 verification_owner 含 ENTAILMENT、condition applies 的字段。
    返回字段名列表（含空字段——空字段由 harness 生成 EMPTY_FIELD_EXECUTION_RECORD）。
    """
    return [x["field_name"] for x in owner_obligations_for_obj(obj, obligations)
            if x["owner"] == "ENTAILMENT" and x["required"]]
