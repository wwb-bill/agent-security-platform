import hashlib
import re
import secrets
from dataclasses import dataclass, field

@dataclass
class CanaryToken:
    id: str
    value: str
    injected_at: str
    agent_id: str
    metadata: dict = field(default_factory=dict)

@dataclass
class CanaryResult:
    detected: bool
    leaked_tokens: list
    context: str

def generate_canary(agent_id: str, context: str = "", prefix: str = "CANARY") -> CanaryToken:
    rand = secrets.token_hex(8)
    value = f"{prefix}-{rand}"
    token_id = hashlib.sha256(value.encode()).hexdigest()[:16]
    return CanaryToken(id=token_id, value=value, injected_at=context, agent_id=agent_id)

def inject_canary(prompt: str, token: CanaryToken, position: str = "end") -> str:
    if position == "end": return f"{prompt}\n\n<!-- {token.value} -->"
    elif position == "beginning": return f"<!-- {token.value} -->\n\n{prompt}"
    return f"{prompt} <!-- {token.value} -->"

def detect_canaries(content: str, known_tokens: list) -> CanaryResult:
    leaked = []
    for t in known_tokens:
        if re.search(re.escape(t.value), content): leaked.append(t)
    return CanaryResult(detected=len(leaked) > 0, leaked_tokens=leaked, context=content[:200])

def batch_generate(agent_id: str, count: int = 5, prefix: str = "CANARY") -> list:
    return [generate_canary(agent_id, f"batch-{i}", prefix) for i in range(count)]