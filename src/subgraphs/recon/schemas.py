from typing import Optional, List, Literal
from pydantic import BaseModel

class PlannerArguments(BaseModel):
    target: Optional[str] = None
    options: Optional[List[str]] = None

class PlannerSchema(BaseModel):
    done: bool
    tool: Literal["nmap", "dig", None]
    arguments: PlannerArguments
    thought: str
    message_for_supervisor: str