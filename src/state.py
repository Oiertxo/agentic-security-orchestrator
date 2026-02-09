from typing import Annotated, List, TypedDict
from langchain_core.messages import BaseMessage
import operator

class AgentState(TypedDict):
    # target: str
    # generated_commands: Annotated[List[str], operator.add]
    # scan_results: str
    # is_safe: bool
    # review_feedback: str
    # logs: Annotated[List[str], operator.add]
    messages: Annotated[List[BaseMessage], operator.add]
    next_step: str
