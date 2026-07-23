from dataclasses import dataclass, field
from enum import Enum

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class RuleCategory(Enum):
    TROJAN = "trojan"
    INJECTION = "injection"
    MEMORY = "memory"
    ARCHITECTURAL = "architectural"
    GENERAL = "general"

@dataclass
class Threat:
    rule_id: str
    category: RuleCategory
    severity: Severity
    description: str
    evidence: str
    agent_id: str = "unknown"
    score: float = 0.0

@dataclass
class SecurityRule:
    id: str
    name: str
    description: str
    category: RuleCategory
    severity: Severity
    def check(self, content: str, agent_id: str = "unknown") -> list:
        raise NotImplementedError

@dataclass
class ScanResult:
    agent_id: str
    threats: list = field(default_factory=list)
    passed: bool = True
    @property
    def critical_count(self) -> int:
        return sum(1 for t in self.threats if t.severity == Severity.CRITICAL)
    def summary(self) -> dict:
        return {"agent_id":self.agent_id,"threats":len(self.threats),"critical":self.critical_count,"passed":self.passed}

@dataclass
class SecurityPolicy:
    max_severity: Severity = Severity.HIGH
    blocked_categories: list = field(default_factory=list)
    fail_on_critical: bool = True
    def allows(self, threat) -> bool:
        if threat.category in self.blocked_categories: return False
        if threat.severity == Severity.CRITICAL and self.fail_on_critical: return False
        return True