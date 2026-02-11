from typing import TypedDict, List, Annotated
from langchain_core.messages import BaseMessage
import operator

class ReconState(TypedDict):
    messages: Annotated[List[BaseMessage], operator.add]
    results: Annotated[List[dict], operator.add]
    done: bool
    step_count: int