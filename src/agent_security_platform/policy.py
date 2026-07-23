from dataclasses import dataclass, field
from .types import ScanResult
from .scanner import SecurityScanner
from .sandbox import MemorySandbox, Capability
from .guard import CircuitBreaker, RateLimitGuard, SessionIntegrityGuard
from .canary import CanaryToken, detect_canaries

@dataclass
class SecurityVerdict:
    passed: bool
    scanner: ScanResult | None = None
    circuit_allowed: bool = True
    rate_allowed: bool = True
    session_valid: bool = True
    canary_leak: bool = False
    violations: list = field(default_factory=list)
    def summary(self) -> dict:
        return {"passed":self.passed,"scanner_passed":self.scanner.passed if self.scanner else None,"circuit":"ok" if self.circuit_allowed else "TRIPPED","rate":"ok" if self.rate_allowed else "BLOCKED","session":"ok" if self.session_valid else "INVALID","canary_leak":self.canary_leak,"violations":self.violations}

@dataclass
class SecurityEngine:
    scanner: SecurityScanner = field(default_factory=SecurityScanner)
    sandbox: MemorySandbox = field(default_factory=MemorySandbox)
    circuit: CircuitBreaker = field(default_factory=lambda: CircuitBreaker(name="default"))
    rate_limiter: RateLimitGuard = field(default_factory=RateLimitGuard)
    session_guard: SessionIntegrityGuard = field(default_factory=SessionIntegrityGuard)
    canary_tokens: list = field(default_factory=list)

    def evaluate(self, content: str, agent_id: str, session_id: str = "", memory_region: str = "") -> SecurityVerdict:
        violations = []
        scan = self.scanner.scan(content, agent_id)
        if scan.passed: self.circuit.record_success()
        else: self.circuit.record_failure()
        circuit_ok = self.circuit.allow()
        if not circuit_ok: violations.append("Circuit breaker tripped")
        rate_ok = self.rate_limiter.allow()
        if not rate_ok: violations.append("Rate limit exceeded")
        session_ok = True
        if session_id:
            session_ok = self.session_guard.validate(session_id, agent_id)
            if not session_ok: violations.append("Session invalid")
        canary_leak = False
        if self.canary_tokens:
            r = detect_canaries(content, self.canary_tokens)
            canary_leak = r.detected
            if canary_leak: violations.append(f"Canary leak ({len(r.leaked_tokens)} tokens)")
        if memory_region and not self.sandbox.check_access(agent_id, memory_region, Capability.READ):
            violations.append(f"Memory denied: {memory_region}")
        passed = scan.passed and circuit_ok and rate_ok and session_ok and not canary_leak
        return SecurityVerdict(passed=passed,scanner=scan,circuit_allowed=circuit_ok,rate_allowed=rate_ok,session_valid=session_ok,canary_leak=canary_leak,violations=violations)