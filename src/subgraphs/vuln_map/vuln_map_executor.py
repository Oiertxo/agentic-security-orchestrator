import json

from langchain_core.messages import HumanMessage
from langchain_core.runnables import RunnableConfig
from langfuse import observe

from src.logger import logger
from src.state import AgentState, FoundExploit, VulnMapState
from src.subgraphs.vuln_map.vuln_map_executor_client import (
    call_search_exploit,
    call_search_framework_modules,
)
from src.utils.utils import parse_as_json


@observe(name="Vuln Map executor")
async def vuln_map_executor_node(
    state: AgentState, config: RunnableConfig
) -> AgentState:
    logger.info("[VULN_MAP_EXECUTOR] Entering Vuln map executor")
    old_vuln_map = state.get("vuln_map", {})
    new_step = int(old_vuln_map.get("step_count", 0)) + 1
    found_map = {k: dict(v) for k, v in old_vuln_map.get("found_exploits", {}).items()}
    analyzed_services_for_search = old_vuln_map.get("analyzed_services_for_search", {})
    analyzed_services_for_search = old_vuln_map.get("analyzed_services_for_search", {})
    new_analyzed_services_for_search = {
        ip: {port: list(cves) for port, cves in ports.items()}
        for ip, ports in analyzed_services_for_search.items()
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

        framework_modules = []
        if t_cve:
            logger.info(
                f"[VULN_MAP_EXECUTOR] Searching Metasploit modules for CVE {t_cve}"
            )

            fw_result = await call_search_framework_modules(cve=t_cve)
            if fw_result.get("ok"):
                framework_modules = fw_result.get("modules", [])

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

        # Update found exploits for service
        found_map = old_vuln_map.get("found_exploits", {})
        service_key = f"{target_ip}:{target_port}" if target_port else target_ip
        found_map.setdefault(service_key, {"exploits": [], "framework_modules": []})
        existing_exploits = found_map.get(service_key, {}).get("exploits", [])
        existing_ids = {
            e.get("edb_id") for e in existing_exploits if isinstance(e, dict)
        }

        new_to_add = [
            n for n in new_found_exploits if n.get("edb_id") not in existing_ids
        ]
        found_map[service_key]["exploits"] = existing_exploits + new_to_add

        # Update framework modules for service
        found_map[service_key]["framework_modules"] = list(
            dict.fromkeys(
                found_map[service_key]["framework_modules"] + framework_modules
            )
        )

        target_cve = args.get("cve")

        new_analyzed_services_for_search.setdefault(target_ip, {})
        new_analyzed_services_for_search[target_ip].setdefault(target_port, [])

        if target_cve not in new_analyzed_services_for_search[target_ip][target_port]:
            new_analyzed_services_for_search[target_ip][target_port].append(target_cve)

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
            "framework_modules": framework_modules,
        }
    else:
        summary = {
            "ok": False,
            "error": engine_result.get("error"),
            "tool": "search_exploit",
        }

    logger.info(f"[VULN_MAP_EXECUTOR] Result summary: {summary}")

    updated_vuln_map: VulnMapState = {
        **old_vuln_map,
        "results": (old_vuln_map.get("results", [])) + [summary],
        "step_count": new_step,
        "found_exploits": found_map,
        "analyzed_services_for_search": new_analyzed_services_for_search,
        "finished": False,
    }

    return {
        **state,
        "user_target": state.get("user_target"),
        "vuln_map": updated_vuln_map,
        "next_step": "planner",
    }
