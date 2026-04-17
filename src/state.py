from typing import Any, Dict, List, Literal, Optional, TypedDict

from langchain_core.messages import BaseMessage
from pydantic import BaseModel, Field


class ServiceMeta(TypedDict, total=False):
    name: Optional[str]
    product: Optional[str]
    version: Optional[str]
    extrainfo: Optional[str]
    ostype: Optional[str]


PortMap = Dict[str, Dict[int, ServiceMeta]]


class FoundExploit(BaseModel):
    edb_id: str = Field(..., alias="EDB-ID")
    title: str = Field(..., alias="Title")
    path: str = Field(..., alias="Path")
    platform: str = Field(..., alias="Platform")
    exploit_type: str = Field(..., alias="Type")
    verified: bool = Field(..., alias="Verified")
    target_service: str
    target_port: int
    associated_cve: Optional[str] = None


class PlannerOutput(TypedDict, total=False):
    next_tool: Optional[str]
    arguments: Dict[str, Any]


class WebForm(TypedDict):
    method: Literal["GET", "POST"]
    parameters: List[str]


class WebNode(TypedDict, total=False):
    type: Literal["directory", "file"]
    content: Optional[str]
    forms: List[WebForm]
    children: Dict[str, "WebNode"]


class ReconState(TypedDict, total=False):
    planner: PlannerOutput
    results: List[dict]
    port_map: PortMap
    scanned_hosts: list[str]
    pending_hosts: list[str]
    web_intel: Dict[str, WebNode]
    finished: bool
    step_count: int


class CveState(TypedDict, total=False):
    planner: PlannerOutput
    results: List[dict]
    pending_services_for_cve: Dict[str, List[int]]
    analyzed_services_for_cve: Dict[str, List[int]]
    finished: bool
    step_count: int
    vulnerabilities: Dict[str, List[Dict[str, Any]]]


class VulnMapState(TypedDict, total=False):
    planner: PlannerOutput
    results: List[dict]
    finished: bool
    step_count: int
    analyzed_services_for_search: Dict[str, List[int]]
    pending_services_for_search: Dict[str, List[Dict[str, Any]]]
    found_exploits: Dict[str, List[Dict[str, Any]]]


class AttackSurface(TypedDict):
    # Target info
    service: str
    product: Optional[str]
    version: Optional[str]
    cves: List[str]
    exploit_ids: List[str]

    # Control
    status: Literal["pending", "exploited", "aborted"]
    attempts: int
    max_attempts: int

    # Results
    last_error: Optional[str]
    last_result: Optional[Dict[str, Any]]

    # Memory
    attempted_exploits: Dict[str, str]


class ExploitState(TypedDict, total=False):
    # Control
    finished: bool
    step_count: int

    # Planner
    planner: PlannerOutput

    # Exploitation
    pending_surfaces: Dict[str, AttackSurface]
    exploited_surfaces: Dict[str, AttackSurface]
    aborted_surfaces: Dict[str, AttackSurface]

    # Global results
    compromised_targets: Dict[str, Dict[str, Any]]


class AgentStateRequired(TypedDict):
    user_target: str
    messages: list[BaseMessage]
    next_step: str


class AgentStateOptional(TypedDict, total=False):
    recon: ReconState
    cve: CveState
    vuln_map: VulnMapState
    exploit: ExploitState
    report_finished: bool


class AgentState(AgentStateOptional, AgentStateRequired):
    """Single global state with optional namespaced branches."""

    pass
