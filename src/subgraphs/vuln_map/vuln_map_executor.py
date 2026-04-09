import json

from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from langfuse import observe

from src.logger import logger
from src.state import AgentState, FoundExploit, VulnMapState
from src.subgraphs.vuln_map.vuln_map_executor_client import call_search_exploit
from src.utils.utils import parse_as_json


@observe(name="Vuln Map executor")
async def vuln_map_executor_node(
    state: AgentState, config: RunnableConfig
) -> AgentState:
    logger.info(f"[VULN_MAP_EXECUTOR] Received state: {state}")
    old_vuln_map = state.get("vuln_map", {})
    new_step = int(old_vuln_map.get("step_count", 0)) + 1
    found_map = dict(old_vuln_map.get("found_exploits", {}))
    analyzed_services_for_search = old_vuln_map.get("analyzed_services_for_search", {})
    new_analyzed_services_for_search = {
        ip: list(ports) for ip, ports in analyzed_services_for_search.items()
    }

    raw = state["messages"][-1].content
    try:
        plan = parse_as_json(raw)
    except Exception:
        result = {"ok": False, "error": "planner_output_not_json", "raw": raw}
        return {
            **state,
            "messages": [
                HumanMessage(content=f"[SOURCE: vuln_map_engine]\n{json.dumps(result)}")
            ],
            "vuln_map": {
                **old_vuln_map,
                "results": (old_vuln_map.get("results", [])) + [result],
                "step_count": new_step,
            },
            "next_step": "planner",
        }

    args = plan.get("arguments", {})
    target_ip = args.get("target").split(":")[0]
    target_port = args.get("port")

    engine_result = await call_search_exploit(plan=plan)

    if engine_result.get("ok"):
        raw_exploits = engine_result.get("response", {}).get("results", [])
        raw_exploits.sort(
            key=lambda x: (x.get("Verified") == "1", x.get("EDB-ID")), reverse=True
        )
        top_raw_exploits = raw_exploits[:3]
        llm_args = plan.get("arguments", {})

        t_service = llm_args.get("service") or "unknown"
        t_port = int(llm_args.get("port") or 0)
        t_cve = llm_args.get("cve")

        new_found_exploits = []
        for exp in top_raw_exploits:
            try:
                exp.update(
                    {
                        "target_service": t_service,
                        "target_port": t_port,
                        "associated_cve": t_cve,
                    }
                )
                exploit_obj = FoundExploit.model_validate(exp)
                new_found_exploits.append(exploit_obj.model_dump())
            except Exception as e:
                logger.warning(f"Validation error: {e}")

        found_map = old_vuln_map.get("found_exploits", {})
        service_key = f"{target_ip}:{target_port}" if target_port else target_ip
        existing_exploits = found_map.get(service_key, [])
        existing_ids = {
            e.get("edb_id") for e in existing_exploits if isinstance(e, dict)
        }

        new_to_add = [
            n for n in new_found_exploits if n.get("edb_id") not in existing_ids
        ]
        found_map[service_key] = existing_exploits + new_to_add

        new_analyzed_services_for_search.setdefault(target_ip, [])
        if target_port not in new_analyzed_services_for_search[target_ip]:
            new_analyzed_services_for_search[target_ip].append(target_port)

        summary = {
            "ok": True,
            "tool": "search_exploit",
            "target": service_key,
            "args": args,
            "count": len(new_found_exploits),
            "top_exploits": [
                {"id": exp.get("edb_id"), "title": exp.get("title")}
                for exp in new_found_exploits[:5]
            ],
        }
    else:
        summary = {
            "ok": False,
            "error": engine_result.get("error"),
            "tool": "search_exploit",
        }

    port_map = state.get("recon", {}).get("port_map", {})
    pending_services_for_search = {}

    for ip, ports in port_map.items():
        searched_exploit_ip = new_analyzed_services_for_search.get(ip, [])

        for port, info in ports.items():
            product = info.get("product")
            version = info.get("version")

            if product and version:
                if port not in searched_exploit_ip:
                    pending_services_for_search.setdefault(ip, []).append(
                        {"port": port, "product": product, "version": version}
                    )

    logger.info(f"[VULN_MAP_EXECUTOR] Result summary: {summary}")

    updated_vuln_map: VulnMapState = {
        **old_vuln_map,
        "results": (old_vuln_map.get("results", [])) + [summary],
        "step_count": new_step,
        "found_exploits": found_map,
        "analyzed_services_for_search": new_analyzed_services_for_search,
        "pending_services_for_search": pending_services_for_search,
        "finished": False,
    }

    return {
        **state,
        "user_target": state.get("user_target"),
        "vuln_map": updated_vuln_map,
        "next_step": "planner",
    }
