import re
from .types import SecurityRule, Threat, Severity, RuleCategory

class TrojanPatternRule(SecurityRule):
    def __init__(self):
        super().__init__(id="asp:trojan-trigger",name="Trojan trigger",description="Detects Trojan agent triggers",category=RuleCategory.TROJAN,severity=Severity.CRITICAL)
    def check(self, content, agent_id="unknown"):
        pts=[r"ignore\s+(?:all\s+)?previous\s+(?:instructions|rules)",r"you\s+are\s+now\s+(?:acting|playing)",r"new\s+system\s+prompt",r"<\|im_start\|>",r"<<SYS>>"]
        th=[]
        for p in pts:
            for m in re.finditer(p,content,re.IGNORECASE):
                th.append(Threat(rule_id=self.id,category=self.category,severity=self.severity,description="Trojan trigger",evidence=m.group(),agent_id=agent_id,score=80))
        return th

class InjectionPatternRule(SecurityRule):
    def __init__(self):
        super().__init__(id="asp:injection",name="Prompt injection",description="Detects injection vectors",category=RuleCategory.INJECTION,severity=Severity.HIGH)
    def check(self, content, agent_id="unknown"):
        pts=[r"disregard\s+(?:all\s+)?(?:previous\s+)?(?:instructions|rules|constraints)",r"<\|im_end\|>",r"system\s*:\s*override"]
        th=[]
        for p in pts:
            for m in re.finditer(p,content,re.IGNORECASE):
                th.append(Threat(rule_id=self.id,category=self.category,severity=self.severity,description="Injection pattern",evidence=m.group(),agent_id=agent_id,score=60))
        return th

class SuspiciousToolCallRule(SecurityRule):
    def __init__(self):
        super().__init__(id="asp:suspicious-tool",name="Suspicious tool",description="Detects dangerous tool calls",category=RuleCategory.ARCHITECTURAL,severity=Severity.HIGH)
    def check(self, content, agent_id="unknown"):
        pts=[r"\brm\s+-(?:rf|fr)\b",r"\bcurl\b.*\|\s*(?:sh|bash)",r"\beval\s*\(.*\)",r"\bsudo\b"]
        th=[]
        for p in pts:
            for m in re.finditer(p,content,re.IGNORECASE):
                th.append(Threat(rule_id=self.id,category=self.category,severity=self.severity,description="Suspicious tool",evidence=m.group(),agent_id=agent_id,score=70))
        return th

class DataExfilRule(SecurityRule):
    def __init__(self):
        super().__init__(id="asp:data-exfil",name="Data exfil",description="Detects data exfiltration",category=RuleCategory.MEMORY,severity=Severity.CRITICAL)
    def check(self, content, agent_id="unknown"):
        pts=[r"(?:OPENAI|ANTHROPIC|GOOGLE|AWS|GITHUB)_?(?:API)?_?KEY",r"cat\s+~/\\.env",r"printenv"]
        th=[]
        for p in pts:
            for m in re.finditer(p,content,re.IGNORECASE):
                th.append(Threat(rule_id=self.id,category=self.category,severity=self.severity,description="Data exfil",evidence=m.group(),agent_id=agent_id,score=90))
        return th

BUILTIN_RULES = [TrojanPatternRule(),InjectionPatternRule(),SuspiciousToolCallRule(),DataExfilRule()]