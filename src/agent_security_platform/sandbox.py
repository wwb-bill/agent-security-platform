from dataclasses import dataclass, field
from enum import Enum

class Capability(Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    RECALL = "recall"

class PermissionError(Exception): pass

@dataclass
class MemoryRegion:
    name: str
    owner_agent: str
    data: dict = field(default_factory=dict)
    capabilities: dict = field(default_factory=dict)
    access_log: list = field(default_factory=list)

    def grant(self, agent: str, *caps: Capability):
        for c in caps: self.capabilities.setdefault(agent, set()).add(c)
        self.access_log.append({"action":"grant","agent":agent,"capabilities":[c.value for c in caps]})

    def revoke(self, agent: str, cap: Capability):
        if agent in self.capabilities: self.capabilities[agent].discard(cap)
        self.access_log.append({"action":"revoke","agent":agent,"capability":cap.value})

    def has_capability(self, agent: str, cap: Capability) -> bool:
        if agent == self.owner_agent: return True
        return cap in self.capabilities.get(agent, set())

    def write(self, agent: str, key: str, value: str):
        if not self.has_capability(agent, Capability.WRITE): raise PermissionError(f"Agent {agent} lacks WRITE on {self.name}")
        self.data[key] = value

    def read(self, agent: str, key: str) -> str:
        if not self.has_capability(agent, Capability.READ): raise PermissionError(f"Agent {agent} lacks READ on {self.name}")
        return self.data.get(key, "")

    def recall(self, agent: str) -> dict:
        if not self.has_capability(agent, Capability.RECALL): raise PermissionError(f"Agent {agent} lacks RECALL on {self.name}")
        return dict(self.data)


class MemorySandbox:
    def __init__(self): self.regions: dict[str, MemoryRegion] = {}

    def create_region(self, name: str, owner: str) -> MemoryRegion:
        r = MemoryRegion(name=name, owner_agent=owner)
        r.grant(owner, Capability.READ, Capability.WRITE, Capability.DELETE, Capability.RECALL)
        self.regions[name] = r
        return r

    def get_region(self, name: str) -> MemoryRegion | None: return self.regions.get(name)

    def check_access(self, agent: str, region: str, cap: Capability) -> bool:
        r = self.regions.get(region)
        return r.has_capability(agent, cap) if r else False

    def audit_log(self) -> list:
        log = []
        for r in self.regions.values():
            log.append({"region":r.name,"owner":r.owner_agent,"granted_agents":list(r.capabilities.keys()),"access_log":r.access_log})
        return log