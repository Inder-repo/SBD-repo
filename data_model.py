
from dataclasses import dataclass, field
from typing import List, Optional, Dict

@dataclass
class Mitigation:
    id: str
    type: str  # Preventive, Detective, Responsive
    control: str

@dataclass
class Threat:
    id: str
    name: str
    category: str  # STRIDE category
    likelihood: int
    impact: int
    risk_score: int = 0
    risk_level: str = ""
    mitigations: List[Mitigation] = field(default_factory=list)
    mitre_ids: List[str] = field(default_factory=list)
    control_refs: List[str] = field(default_factory=list)

@dataclass
class TrustBoundary:
    name: str
    description: str
    components: List[str]
    threats: List[Threat] = field(default_factory=list)

@dataclass
class Component:
    id: str
    name: str
    type: str
    description: str
    x: int
    y: int

@dataclass
class Connection:
    id: str
    source_id: str
    target_id: str
    data_flow: str
    description: str
    trust_boundary_crossing: str
