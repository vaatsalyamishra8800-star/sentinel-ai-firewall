"""
Sentinel - Policy Engine
Maps detection findings to actions: ALLOW, REDACT, or BLOCK.
Enforces hierarchical security rules (BLOCK > REDACT > ALLOW).
"""

from typing import List, Dict, Any
from detector import redact_text

# Default policy action mapping for each finding type
DEFAULT_POLICY_MAP = {
    "prompt_injection": "BLOCK",
    "command_injection": "BLOCK",
    "api_key": "BLOCK",
    "canary_tripwire": "BLOCK",
    "lateral_movement": "BLOCK",
    "card_number": "REDACT",
    "aadhaar": "REDACT",
    "ssn": "REDACT",
    "phone": "REDACT",
    "email": "REDACT",
}

# Precedence levels for conflicting actions
PRECEDENCE = {
    "BLOCK": 3,
    "REDACT": 2,
    "ALLOW": 1
}


def evaluate_policy(findings: List[Dict[str, Any]], original_text: str, custom_policy: Dict[str, str] = None) -> Dict[str, Any]:
    """
    Evaluates findings against active policies.
    Returns:
        action: 'ALLOW', 'REDACT', or 'BLOCK'
        reason: Summary explanation of the decision
        sanitized_text: Redacted text if action is REDACT or original if ALLOW (or empty if BLOCK)
        violations: List of specific finding types triggered
    """
    policy_map = dict(DEFAULT_POLICY_MAP)
    if custom_policy:
        policy_map.update(custom_policy)

    if not findings:
        return {
            "action": "ALLOW",
            "reason": "No security violations or sensitive data detected.",
            "sanitized_text": original_text,
            "violations": []
        }

    highest_action = "ALLOW"
    violation_reasons = []
    violation_types = []

    for f in findings:
        ftype = f["type"]
        violation_types.append(ftype)
        action_for_type = policy_map.get(ftype, "ALLOW").upper()

        if PRECEDENCE.get(action_for_type, 1) > PRECEDENCE.get(highest_action, 1):
            highest_action = action_for_type

        violation_reasons.append(f"{f['description']} ('{ftype}')")

    unique_violations = sorted(list(set(violation_types)))
    reason_str = ", ".join(list(dict.fromkeys(violation_reasons)))

    if highest_action == "BLOCK":
        return {
            "action": "BLOCK",
            "reason": f"Blocked due to high-risk violation: {reason_str}",
            "sanitized_text": None,
            "violations": unique_violations
        }
    elif highest_action == "REDACT":
        sanitized = redact_text(original_text, findings)
        return {
            "action": "REDACT",
            "reason": f"Sensitive data sanitized: {reason_str}",
            "sanitized_text": sanitized,
            "violations": unique_violations
        }
    else:
        return {
            "action": "ALLOW",
            "reason": "Allowed by policy exemptions.",
            "sanitized_text": original_text,
            "violations": unique_violations
        }
