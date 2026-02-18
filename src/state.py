from typing import TypedDict, List, Dict, Any, Optional
from typing_extensions import Annotated
from langchain_core.messages import BaseMessage
import operator

class PlannerOutput(TypedDict, total=False):
    done: bool
    tool: Optional[str]
    arguments: Dict[str, Any]
    thought: str
    message_for_supervisor: str

class ReconState(TypedDict, total=False):
    planner: PlannerOutput
    results: Annotated[List[dict], operator.add]
    port_map: dict[str, list[int]]
    scanned_hosts: list[str]
    pending_hosts: list[str]
    done: bool
    step_count: int

class ExploitState(TypedDict, total=False):
    planner: PlannerOutput
    findings: List[Dict[str, Any]]
    attempted: List[Dict[str, Any]]
    done: bool
    step_count: int

class AgentStateRequired(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    next_step: str

class AgentStateOptional(TypedDict, total=False):
    recon: ReconState
    exploit: ExploitState

class AgentState(AgentStateRequired, AgentStateOptional):
    """Single global state with optional namespaced branches."""
    pass