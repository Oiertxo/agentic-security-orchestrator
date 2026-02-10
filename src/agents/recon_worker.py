from langchain_core.messages import AIMessage
from src.state import AgentState

def recon_worker_node(state: AgentState):
    print("--- MOCK RECON ---")

    technical_output = """
        [SOURCE: RECON]
        TARGET_RANGE: 192.168.1.0/24
        FINDINGS: 
        - Port 22 (SSH) on 192.168.1.13: OPEN WITHOUT PASSWORD
        [/END_REPORT]
        """
    
    return AgentState(
        messages=[AIMessage(content=technical_output)],
        next_step="supervisor"
    )