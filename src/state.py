from typing import TypedDict, List, Dict, Any, Optional
from typing_extensions import Annotated
from langchain_core.messages import BaseMessage
from pydantic import BaseModel, Field
import operator

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

class ReconState(TypedDict, total=False):
    planner: PlannerOutput
    results: Annotated[List[dict], operator.add]
    port_map: PortMap
    scanned_hosts: list[str]
    pending_hosts: list[str]
    finished: bool
    step_count: int

class CveState(TypedDict, total=False):
    planner: PlannerOutput
    results: Annotated[List[dict], operator.add]
    port_map: PortMap
    pending_services_for_cve: Dict[str, List[int]]
    analyzed_services_for_cve: Dict[str, List[int]]
    finished: bool
    step_count: int
    vulnerabilities: Dict[str, List[Dict[str, Any]]]

class ExploitState(TypedDict, total=False):
    planner: PlannerOutput
    results: Annotated[List[dict], operator.add]
    port_map: PortMap
    analyzed_services_for_cve: Dict[str, List[int]]
    pending_services_for_cve: Dict[str, List[int]]
    finished: bool
    step_count: int
    vulnerabilities: Dict[str, List[Dict[str, Any]]]
    analyzed_services_for_search: Dict[str, List[int]]
    pending_services_for_search: Dict[str, List[Dict[str, Any]]]
    found_exploits: Dict[str, List[FoundExploit]]

class AgentStateRequired(TypedDict):
    user_target: str
    messages: list[BaseMessage]
    next_step: str

class AgentStateOptional(TypedDict, total=False):
    recon: ReconState
    cve: CveState
    exploit: ExploitState
    report_finished: bool

class AgentState(AgentStateOptional, AgentStateRequired):
    """Single global state with optional namespaced branches."""
    pass