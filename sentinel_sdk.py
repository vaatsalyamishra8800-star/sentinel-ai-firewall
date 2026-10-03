"""
Sentinel SDK - Zero-Dependency Drop-in AI Firewall Client
Use this SDK to protect any LLM framework (LangChain, CrewAI, AutoGen, LlamaIndex, OpenAI, Claude).

Example Usage:
--------------
from sentinel_sdk import guard_prompt, guard_tool, SentinelQuarantineError, SentinelSecurityError

# 1. Inspect and sanitize prompts:
sanitized_prompt = guard_prompt("Charge to Visa 4242 4242 4242 4242", agent_name="CheckoutAgent")

# 2. Decorate tool functions with zero-trust execution guards:
@guard_tool(agent_name="DbWorker")
def run_db_query(sql_query: str):
    return execute_query(sql_query)
"""

import json
import urllib.request
import urllib.error
from functools import wraps
from typing import Dict, Any, Optional, Callable

DEFAULT_GATEWAY_URL = "http://localhost:8080"


class SentinelSecurityError(Exception):
    """Raised when Sentinel Gateway blocks an unsafe prompt or tool call."""
    pass


class SentinelQuarantineError(SentinelSecurityError):
    """Raised when the agent invoking the tool has been quarantined by Sentinel."""
    pass


def inspect_prompt(
    prompt: str,
    agent_name: str = "ClientAgent",
    gateway_url: str = DEFAULT_GATEWAY_URL,
    timeout: float = 5.0
) -> Dict[str, Any]:
    """
    Sends a prompt to Sentinel Gateway for real-time inspection.
    Returns the parsed JSON verdict from Sentinel.
    """
    endpoint = f"{gateway_url.rstrip('/')}/inspect"
    payload = json.dumps({"agent": agent_name, "prompt": prompt}).encode("utf-8")
    
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def guard_prompt(
    prompt: str,
    agent_name: str = "ClientAgent",
    gateway_url: str = DEFAULT_GATEWAY_URL,
    fail_closed: bool = True
) -> str:
    """
    Guards a prompt before sending to an LLM:
    - ALLOW : Returns original prompt intact
    - REDACT: Returns in-flight sanitized prompt with PII scrubbed
    - BLOCK : Raises SentinelSecurityError or SentinelQuarantineError
    """
    try:
        verdict = inspect_prompt(prompt, agent_name=agent_name, gateway_url=gateway_url)
    except Exception as e:
        if fail_closed:
            raise SentinelSecurityError(f"Sentinel Gateway unreachable: {e}")
        return prompt

    if verdict.get("action") == "BLOCK":
        if verdict.get("quarantined"):
            raise SentinelQuarantineError(f"Agent '{agent_name}' is QUARANTINED: {verdict.get('reason')}")
        raise SentinelSecurityError(f"Blocked by Sentinel Policy: {verdict.get('reason')}")

    if verdict.get("action") == "REDACT":
        return verdict.get("sanitized_text") or prompt

    return prompt


def inspect_tool_call(
    tool_name: str,
    arguments: Dict[str, Any],
    agent_name: str = "ClientAgent",
    gateway_url: str = DEFAULT_GATEWAY_URL,
    timeout: float = 5.0
) -> Dict[str, Any]:
    """
    Sends a tool invocation and arguments to Sentinel Zero-Trust Tool Firewall.
    """
    endpoint = f"{gateway_url.rstrip('/')}/inspect_tool"
    payload = json.dumps({
        "agent": agent_name,
        "tool_name": tool_name,
        "arguments": arguments
    }).encode("utf-8")

    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def guard_tool(
    agent_name: str = "ToolAgent",
    gateway_url: str = DEFAULT_GATEWAY_URL,
    fail_closed: bool = True
):
    """
    Decorator for tool functions.
    Intercepts function arguments, verifies permissions, sanitizes PII,
    and halts dangerous commands before the tool executes.
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            tool_name = func.__name__
            # Map keyword arguments and positional arguments
            arg_dict = dict(kwargs)
            for idx, val in enumerate(args):
                arg_dict[f"arg_{idx}"] = val

            try:
                verdict = inspect_tool_call(
                    tool_name=tool_name,
                    arguments=arg_dict,
                    agent_name=agent_name,
                    gateway_url=gateway_url
                )
            except Exception as e:
                if fail_closed:
                    raise SentinelSecurityError(f"Sentinel Tool Firewall unreachable: {e}")
                return func(*args, **kwargs)

            if not verdict.get("execution_allowed"):
                if verdict.get("quarantined"):
                    raise SentinelQuarantineError(f"Quarantined agent denied execution of '{tool_name}': {verdict.get('reason')}")
                raise SentinelSecurityError(f"Tool execution blocked: {verdict.get('reason')}")

            # If sanitized arguments returned, update kwargs
            sanitized = verdict.get("sanitized_arguments") or {}
            new_kwargs = {}
            for k, v in kwargs.items():
                new_kwargs[k] = sanitized.get(k, v)

            # Reconstruct positional args if sanitized
            new_args = list(args)
            for idx in range(len(args)):
                key = f"arg_{idx}"
                if key in sanitized:
                    new_args[idx] = sanitized[key]

            return func(*new_args, **new_kwargs)
        return wrapper
    return decorator


def generate_canary(
    agent_name: str = "ClientAgent",
    label: str = "SDK System Prompt Canary",
    gateway_url: str = DEFAULT_GATEWAY_URL
) -> str:
    """
    Requests a fresh cryptographic HoneyPrompt Canary Token from Sentinel Gateway.
    Embed this token into the agent's system prompt or scratchpad memory.
    """
    endpoint = f"{gateway_url.rstrip('/')}/canary/generate"
    payload = json.dumps({"agent": agent_name, "label": label}).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        return res.get("canary_token", "")


def guard_agent_hop(
    caller_agent: str,
    target_agent: str,
    gateway_url: str = DEFAULT_GATEWAY_URL,
    fail_closed: bool = True
):
    """
    Decorator for cross-agent RPC / multi-agent dispatch (e.g., AutoGen, CrewAI).
    Validates caller permissions and severs lateral movement privilege escalation attempts.
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            endpoint = f"{gateway_url.rstrip('/')}/inspect"
            payload = json.dumps({
                "agent": target_agent,
                "caller_agent": caller_agent,
                "prompt": str(args) + str(kwargs)
            }).encode("utf-8")
            req = urllib.request.Request(
                endpoint,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            try:
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    verdict = json.loads(resp.read().decode("utf-8"))
                    if verdict.get("action") == "BLOCK":
                        raise SentinelSecurityError(f"Multi-Agent Cascade Blocked: {verdict.get('reason')}")
            except Exception as e:
                if fail_closed:
                    raise SentinelSecurityError(f"Sentinel Lateral Guard blocked dispatch: {e}")
            return func(*args, **kwargs)
        return wrapper
    return decorator

