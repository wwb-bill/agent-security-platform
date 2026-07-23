from .types import ScanResult, SecurityPolicy, Severity
from .rules import BUILTIN_RULES, SecurityRule

class SecurityScanner:
    def __init__(self, policy=None, rules=None):
        self.policy = policy or SecurityPolicy()
        self.rules = rules or BUILTIN_RULES

    def scan(self, content, agent_id="unknown"):
        threats = []
        for rule in self.rules:
            threats.extend(rule.check(content, agent_id))
        has_critical = any(t.severity == Severity.CRITICAL for t in threats)
        passed = not (has_critical and self.policy.fail_on_critical)
        return ScanResult(agent_id=agent_id, threats=threats, passed=passed)

    def scan_batch(self, items):
        return [self.scan(content, agent_id) for content, agent_id in items]

    def add_rule(self, rule):
        self.rules.append(rule)