from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langfuse import observe
from src.state import AgentState
from src.logger import logger
from src.model import get_model
from src.utils.utils import load_prompt
from src.utils.toon_formatter import port_map_to_toon, vulnerabilities_to_toon, found_exploits_to_toon
from typing import Dict, Any

@observe(name="Report Worker")
async def report_worker_node(state: AgentState, config: RunnableConfig) -> AgentState:
    llm = get_model()
    system_prompt = load_prompt("report.txt")
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("system", "Target requested by the user: {target}"),
        ("system", "Port map (host and their open ports): {port_map}"),
        ("system", "Vulnerabilities found: {vulnerabilities}"),
        ("system", "Exploit scripts identified in database: {found_exploits}"),
        ("system", "Exploit findings {exploit_state}")
    ])

    recon_data = state.get("recon", {})
    cve_data = state.get("cve", {})
    vuln_map_data = state.get("vuln_map", {})
    exploit_state = state.get("exploit", {})

    planner_input: Dict[str, Any] = {
        "target": state["user_target"],
        "port_map": port_map_to_toon(recon_data.get("port_map", {})),
        "vulnerabilities": vulnerabilities_to_toon(cve_data.get("vulnerabilities", {})),
        "found_exploits": found_exploits_to_toon(vuln_map_data.get("found_exploits", {})),
        "exploit_state": exploit_state
    }

    logger.info(f"[REPORT_WORKER_NODE] Calling LLM: {planner_input}")
    
    chain = prompt | llm | StrOutputParser()

    result = await chain.ainvoke(planner_input, config=config)
    
    logger.info(f"[REPORT_WORKER_NODE] Response from LLM: {result[:20]}")

    with open("/data/reports/final_assessment.md", "w") as f:
        f.write(result)

    return {
        **state,
        "messages": state.get("messages") + [AIMessage(content="Final report generated and saved to /data/reports/")],
        "next_step": "supervisor",
        "report_finished": True
    }