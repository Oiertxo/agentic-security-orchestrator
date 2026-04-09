from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel

class SupervisorSchema(BaseModel):
    user_target: str
    next_step: str
    message: str

class ThoughtSchema(BaseModel):
    step: int
    action: str
    reasoning: str

class PlannerArguments(BaseModel):
    target: Optional[str] = None
    options: Optional[List[str]] = None
    product: Optional[str] = None
    version: Optional[str] = None
    port: Optional[int] = None
    cve: Optional[str] = None

class PlannerSchema(BaseModel):
    finished: bool
    next_tool: Optional[str] = None
    arguments: PlannerArguments
    thought: Optional[ThoughtSchema] = None

class ExploitSchema(BaseModel):
    mode: Literal["executor", "manual"]
    executor: str
    parameters: Optional[Dict[str, Any]] = None
    tool_command: Optional[str] = None
    reasoning: str

class ExploitOutputClassifierSchema(BaseModel):
    classification: str
    reasoning: str

class ExploitFixerSchema(BaseModel):
    result: str
    fixed_script: Optional[str] = None
    reasoning: str