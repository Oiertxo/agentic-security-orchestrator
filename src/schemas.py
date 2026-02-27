from typing import Optional, List, Literal
from pydantic import BaseModel

class SupervisorSchema(BaseModel):
    user_target: str
    next_step: str
    message: str

class PlannerArguments(BaseModel):
    target: Optional[str] = None
    options: Optional[List[str]] = None
    product: Optional[str] = None
    version: Optional[str] = None
    port: Optional[int] = None

class ReconPlannerSchema(BaseModel):
    finished: bool
    next_tool: Literal["nmap", "dig", None]
    arguments: PlannerArguments

class ExploitPlannerSchema(BaseModel):
    finished: bool
    next_tool: Optional[str] = None
    arguments: PlannerArguments