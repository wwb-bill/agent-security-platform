from agent_security_platform.sandbox import MemorySandbox, Capability
from agent_security_platform.canary import generate_canary, inject_canary, detect_canaries, batch_generate
import pytest

class TestMemorySandbox:
    def test_owner_has_access(self):
        sb = MemorySandbox()
        sb.create_region("r1", "agent-a")
        assert sb.check_access("agent-a", "r1", Capability.READ) is True
    def test_outsider_blocked(self):
        sb = MemorySandbox()
        sb.create_region("r1", "agent-a")
        assert sb.check_access("agent-b", "r1", Capability.READ) is False
    def test_grant_and_check(self):
        sb = MemorySandbox()
        sb.create_region("r1", "agent-a")
        r = sb.get_region("r1")
        r.grant("agent-b", Capability.READ)
        assert sb.check_access("agent-b", "r1", Capability.READ) is True
    def test_write_and_read(self):
        sb = MemorySandbox()
        sb.create_region("r1", "agent-a")
        r = sb.get_region("r1")
        r.write("agent-a", "key1", "secret-value")
        assert r.read("agent-a", "key1") == "secret-value"
    def test_write_permission_denied(self):
        sb = MemorySandbox()
        sb.create_region("r1", "agent-a")
        with pytest.raises(Exception):
            sb.get_region("r1").write("agent-b", "x", "y")
    def test_revoke(self):
        sb = MemorySandbox()
        sb.create_region("r1", "agent-a")
        r = sb.get_region("r1")
        r.grant("agent-b", Capability.READ)
        r.revoke("agent-b", Capability.READ)
        assert sb.check_access("agent-b", "r1", Capability.READ) is False

class TestCanary:
    def test_unique(self):
        assert generate_canary("a").value != generate_canary("a").value
    def test_inject_end(self):
        c = generate_canary("a")
        result = inject_canary("Hello", c)
        assert c.value in result
    def test_detect(self):
        c1 = generate_canary("a", prefix="X")
        prompt = inject_canary("Hello", c1)
        result = detect_canaries(prompt, [c1])
        assert result.detected is True
    def test_batch(self):
        tokens = batch_generate("agent-1", count=3)
        assert len(tokens) == 3