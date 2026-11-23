"""Current-fact fingerprints for the two independent closing signatures.

A closing signature is never tied to a whole batch identity (that would force
both reviewers to re-sign whenever any byte of the source changes) and it is
never tied to the money total alone (that would silently publish a version
whose coverage source changed while the amount stayed the same).

Instead every role signs the layer it is actually responsible for:

* 保障 (coverage)  -> the current liability intervals and their source rows
* 财务 (finance)   -> the current supplement/refund amounts

The fingerprints are canonical and stable across JSON storage and across
batches.  A signature therefore carries over to a later batch exactly when
the facts in its own layer are unchanged.
"""
import hashlib
import json

from app.config import RULE_VERSION
from app.errors import DomainError

# Canonical role names used by storage, API and evidence.
COVERAGE = "保障"
FINANCE = "财务"
ROLES = (COVERAGE, FINANCE)
ROLE_LABELS = {COVERAGE: "责任区间", FINANCE: "补退金额"}

_ROLE_ALIASES = {
    "保障": COVERAGE,
    "保障复核": COVERAGE,
    "coverage": COVERAGE,
    "guarantee": COVERAGE,
    "underwriting": COVERAGE,
    "insurance": COVERAGE,
    "财务": FINANCE,
    "财务复核": FINANCE,
    "finance": FINANCE,
    "financial": FINANCE,
    "actuarial": FINANCE,
}

_DECISION_ALIASES = {
    "通过": "通过",
    "同意": "通过",
    "approve": "通过",
    "approved": "通过",
    "pass": "通过",
    "退回": "退回",
    "驳回": "退回",
    "reject": "退回",
    "rejected": "退回",
    "return": "退回",
}


def normalize_role(role):
    if role is None:
        raise DomainError("ROLE", "请提交复核角色（保障/财务）")
    key = str(role).strip()
    normalized = _ROLE_ALIASES.get(key) or _ROLE_ALIASES.get(key.lower())
    if normalized is None:
        raise DomainError("ROLE", "复核角色无效，应为保障或财务")
    return normalized


def normalize_decision(decision):
    if decision is None:
        return "通过"
    key = str(decision).strip()
    normalized = _DECISION_ALIASES.get(key) or _DECISION_ALIASES.get(key.lower())
    if normalized is None:
        raise DomainError("DECISION", "复核状态无效")
    return normalized


def canonical(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    )


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def evidence_checksum(signatures):
    """Hash of the signature evidence rows that accompany an export."""
    normalized = [dict(row) for row in signatures]
    return hashlib.sha256(canonical(normalized).encode("utf-8")).hexdigest()


def _text(value):
    return "" if value is None else str(value)


def coverage_facts(state):
    """The current liability intervals, including which row is their source.

    Money is deliberately absent: a premium-only correction belongs to the
    finance signature.  Source identity is deliberately present: swapping an
    endorsement for another one with identical dates and premium is still a
    coverage change that the coverage reviewer must see.
    """
    segments = {}
    for row in state.get("segments", []) or []:
        segments.setdefault(row.get("id"), []).append(row)

    policies = []
    for policy in state.get("policies", []) or []:
        base = policy.get("base") or {}
        changes = []
        for change in policy.get("changes", []) or []:
            changes.append(
                {
                    "source": _text(change.get("id")),
                    "effective": _text(change.get("effective")),
                    "version": _text(change.get("version")),
                    "cover": _text(change.get("cover")),
                }
            )
        changes.sort(key=lambda row: (row["effective"], row["version"], row["source"]))
        spans = []
        for span in segments.get(policy.get("id"), []):
            spans.append(
                {
                    "source": _text(span.get("source")),
                    "start": _text(span.get("start")),
                    "end": _text(span.get("end")),
                    "days": span.get("days"),
                    "year_days": span.get("year_days"),
                }
            )
        spans.sort(key=lambda row: (row["start"], row["end"], row["source"]))
        policies.append(
            {
                "id": _text(policy.get("id")),
                "base": {
                    "source": _text(base.get("id")),
                    "start": _text(base.get("start")),
                    "end": _text(base.get("end")),
                    "cover": _text(base.get("cover")),
                },
                "changes": changes,
                "cancelled": sorted(_text(x) for x in policy.get("cancelled", []) or []),
                "segments": spans,
            }
        )
    policies.sort(key=lambda row: row["id"])
    return {
        "scope": "coverage",
        "rule_version": RULE_VERSION,
        "policies": policies,
    }


def finance_facts(state):
    """The current supplement/refund amounts only.

    The allocation is represented by each segment's premium, not by its
    calendar boundaries or source row.  A re-sourced but amount-identical
    endorsement therefore leaves the finance signature valid.
    """
    calculations = []
    for calculation in state.get("calculations", []) or []:
        calculations.append(
            {
                "id": _text(calculation.get("id")),
                "code": _text(calculation.get("code")),
                "expected": _text(calculation.get("expected")),
                "paid": _text(calculation.get("paid")),
                "difference": _text(calculation.get("difference")),
                "premiums": [
                    _text(segment.get("premium"))
                    for segment in calculation.get("segments", []) or []
                ],
            }
        )
    calculations.sort(key=lambda row: row["id"])
    business = state.get("business") or {}
    return {
        "scope": "finance",
        "rule_version": RULE_VERSION,
        "calculations": calculations,
        "business": {
            "total": _text(business.get("total")),
            "paid": _text(business.get("paid")),
            "difference": _text(business.get("difference")),
            "unit": _text(business.get("unit")),
        },
    }


def role_facts(state):
    return {COVERAGE: coverage_facts(state), FINANCE: finance_facts(state)}


def fact_digests(state):
    return {role: digest(facts) for role, facts in role_facts(state).items()}


def facts_report(state):
    facts = role_facts(state)
    return {
        role: {
            "scope": facts[role]["scope"],
            "label": ROLE_LABELS[role],
            "digest": digest(facts[role]),
        }
        for role in ROLES
    }
