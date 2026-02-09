from langchain_core.messages import AIMessage
from src.state import AgentState

def mock_worker_node(state: AgentState):
    print("--- MOCK WORKER ---")

    technical_output = """
        [SOURCE: NETWORK_SCANNER_WORKER]
        TARGET_RANGE: 192.168.1.0/24
        FINDINGS: 
        - Port 9696 (TCP): OPEN
        - Traffic: Suspicious/Unrecognized
        - Status: ALERT
        [/END_REPORT]
        """
    
    return AgentState(
        messages=[AIMessage(content=technical_output)],
        next_step="supervisor"
    )