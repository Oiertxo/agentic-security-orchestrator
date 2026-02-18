from typing import Optional, List, Literal
from pydantic import BaseModel

class SupervisorSchema(BaseModel):
    next_step: str
    message: str

class ReconPlannerArguments(BaseModel):
    target: Optional[str] = None
    options: Optional[List[str]] = None

class ReconPlannerSchema(BaseModel):
    done: bool
    tool: Literal["nmap", "dig", None]
    arguments: ReconPlannerArguments
    thought: str
    message_for_supervisor: str