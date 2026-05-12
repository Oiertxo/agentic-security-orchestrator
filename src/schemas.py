from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field


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
    reasoning: Optional[str] = None
    thought: Optional[ThoughtSchema] = None


class ExploitPayloadStep(BaseModel):
    action: Literal["send", "recv"] = Field(
        ..., description="Type of interaction performed by the exploit"
    )
    data: str = Field(..., description="Literal payload data or expected pattern")


class ExploitSemanticSchema(BaseModel):
    is_framework_module: bool = Field(
        ..., description="True if this exploit is a Metasploit framework module"
    )
    exploit_behavior: Literal[
        "bind_shell",
        "reverse_shell",
        "http_rce",
        "generic_rce",
        "metasploit",
        "enumeration",
        "other",
    ] = Field(..., description="High-level behavior of the exploit")
    input_mode: Literal["arguments", "stdin", "interactive", "other"] = Field(
        ..., description="General argument input mode of the exploit"
    )
    arguments: List[
        Literal["RHOST", "RPORT", "LHOST", "LPORT", "BIND_PORT", "URL", "FILE", "CMD"]
    ] = Field(
        default_factory=list,
        description="Conceptual parameters referenced by the exploit without fixed values",
    )
    hardcoded_values: Dict[str, int | str] = Field(
        default_factory=dict,
        description="Literal constant values embedded in the exploit (ports, paths, filenames, etc.)",
    )


class ExploitPayloadSchema(BaseModel):
    payloads: List[ExploitPayloadStep] = Field(
        default_factory=list,
        description="Ordered exploitation dialogue extracted from the exploit",
    )
