import time
from dataclasses import dataclass, field

class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int = 5, recovery_timeout_s: float = 60):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout_s = recovery_timeout_s
        self.failures = 0
        self.tripped = False
        self.tripped_at = 0.0

    def allow(self) -> bool:
        if self.tripped:
            if time.time() - self.tripped_at > self.recovery_timeout_s:
                self.tripped = False
                self.failures = 0
                return True
            return False
        return True

    def record_failure(self):
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.tripped = True
            self.tripped_at = time.time()

    def record_success(self):
        self.failures = 0
        self.tripped = False


class RateLimitGuard:
    def __init__(self, max_requests: int = 100, window_s: int = 60):
        self.max_requests = max_requests
        self.window_s = window_s
        self.requests: list[float] = []

    def allow(self) -> bool:
        now = time.time()
        self.requests = [t for t in self.requests if now - t < self.window_s]
        if len(self.requests) < self.max_requests:
            self.requests.append(now)
            return True
        return False

    def remaining(self) -> int:
        now = time.time()
        self.requests = [t for t in self.requests if now - t < self.window_s]
        return self.max_requests - len(self.requests)


class SessionIntegrityGuard:
    def __init__(self): self.sessions: dict[str, str] = {}

    def start_session(self, session_id: str, agent_id: str) -> bool:
        if session_id in self.sessions: return False
        self.sessions[session_id] = agent_id
        return True

    def validate(self, session_id: str, agent_id: str) -> bool:
        return self.sessions.get(session_id) == agent_id

    def end_session(self, session_id: str):
        self.sessions.pop(session_id, None)