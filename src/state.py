from typing import TypedDict, List, Dict, Any, Optional
from typing_extensions import Annotated
from langchain_core.messages import BaseMessage
import operator

class ServiceMeta(TypedDict, total=False):
    name: Optional[str]
    product: Optional[str]
    version: Optional[str]
    extrainfo: Optional[str]
    ostype: Optional[str]

PortMap = Dict[str, Dict[int, ServiceMeta]]

class PlannerOutput(TypedDict, total=False):
    finished: bool
    next_tool: Optional[str]
    arguments: Dict[str, Any]
    thought: str
    message_for_supervisor: str

class ReconState(TypedDict, total=False):
    planner: PlannerOutput
    results: Annotated[List[dict], operator.add]
    port_map: PortMap
    scanned_hosts: list[str]
    pending_hosts: list[str]
    finished: bool
    step_count: int

class ExploitState(TypedDict, total=False):
    planner: PlannerOutput
    results: Annotated[List[dict], operator.add]
    port_map: PortMap
    attempted: List[Dict[str, Any]]
    finished: bool
    step_count: int
    vulnerabilities: Dict[str, List[Dict[str, Any]]]
    working_target: Dict[str, Any]

class AgentStateRequired(TypedDict):
    user_target: str
    messages: list[BaseMessage]
    next_step: str

class AgentStateOptional(TypedDict, total=False):
    recon: ReconState
    exploit: ExploitState

class AgentState(AgentStateOptional, AgentStateRequired):
    """Single global state with optional namespaced branches."""
    pass