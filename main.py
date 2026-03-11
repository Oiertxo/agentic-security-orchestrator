import os, sys, requests, uvicorn, sqlite3, time
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig
from src.graph import compile_workflow
from src.state import AgentState
from src.model import get_model
from src.utils.toon_formatter import get_minimal_toon_context
from src.logger import logger
from langfuse.langchain import CallbackHandler
from langgraph.checkpoint.sqlite import SqliteSaver

load_dotenv()

DB_PATH = "/app/data/database/checkpoints.db"
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

def get_memory_saver():
    try:
        # check_same_thread=False allows multiple threads to access the DB connection safely.
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        return SqliteSaver(conn)
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None

# Initialize the saver
memory = get_memory_saver()

app = FastAPI(
    title="Agentic Security Orchestrator",
    description="API for the LangGraph Security Agent System",
    version="0.1.0"
)

langfuse_handler = CallbackHandler()

# Compile the Graph once at startup
try:
    security_graph = compile_workflow(checkpointer=memory)
except Exception as e:
    logger.error(f"CRITICAL: Failed to compile graph: {e}")
    sys.exit(1)

# Define user request
class UserRequest(BaseModel):
    query: str
    thread_id: Optional[str] = "default_thread"
    start_new: bool = Field(default=False, description="If True, wipes existing thread data and starts a fresh audit.")

# Define the API Endpoint
@app.post("/chat")
async def chat_endpoint(request: UserRequest):
    thread_id = request.thread_id or "default_thread"
    query = request.query.lower()
    
    config: RunnableConfig = {
        "configurable": {"thread_id": thread_id, "start_time": time.time()},
        "callbacks": [langfuse_handler]
    }

    try:
        snapshot = security_graph.get_state(config)

        if request.start_new:
            logger.info(f"[MAIN] Force-restarting thread {thread_id}. Wiping old data...")
            await delete_thread(thread_id)
            return await start_fresh_audit(request.query, config, thread_id)

        is_control_command = any(cmd in query for cmd in ["approve", "abort"])

        # Control command without a pause
        if is_control_command and not snapshot.next:
            if not snapshot.values:
                raise HTTPException(status_code=404, detail="Thread not found.")
            else:
                return {
                    "response": f"The thread is already finished. You cannot '{query}' it now.",
                    "status": "error",
                    "thread_id": thread_id
                }
        
        if snapshot.values:
            if snapshot.next:
                # System is paused -> Human in the Loop
                if "approve" in query:
                    result = security_graph.invoke(None, config=config)
                elif "abort" in query:
                    security_graph.update_state(config, {"next_step": "report"})
                    result = security_graph.invoke(None, config=config)
                else:
                    # Consultation mode while paused
                    return await handle_consultation(request.query, snapshot.values, thread_id, is_finished=False)
            else:
                # System has finished (Post-Audit Analysis)
                return await handle_consultation(request.query, snapshot.values, thread_id, is_finished=True)

        # New thread
        else:
            return await start_fresh_audit(request.query, config, thread_id)

        # Final standardized response handling for Graph execution (from invokes above)
        return format_graph_response(result, config, thread_id)

    except Exception as e:
        logger.error(f"Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/threads")
async def list_threads():
    """
    Lists all unique thread IDs stored in the SQLite database.
    This helps the user see previous audits.
    """
    if memory is None:
        logger.error("SqliteSaver memory is not initialized.")
        raise HTTPException(status_code=500, detail="Database connection is down")

    try:
        threads = []
        for checkpoint in memory.list(config=None):
            config = checkpoint.config
            if config and "configurable" in config:
                configurable = config.get("configurable", {})
                t_id = configurable.get("thread_id")
                
                if isinstance(t_id, str) and t_id not in threads:
                    threads.append(t_id)
        
        return {
            "total_threads": len(threads),
            "threads": threads,
        }
    except Exception as e:
        logger.error(f"Error listing threads: {e}")
        raise HTTPException(status_code=500, detail="Could not retrieve threads.")
    
@app.get("/threads/{thread_id}")
async def get_detailed_status(thread_id: str):
    """
    Returns the current progress, identified vulnerabilities, 
    and next steps for a specific audit thread.
    """
    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
    snapshot = security_graph.get_state(config)
    
    if not snapshot.values:
        raise HTTPException(status_code=404, detail="Thread not found.")

    # Calculate some quick stats for the UI
    recon_data = snapshot.values.get("recon", {})
    vuln_data = snapshot.values.get("cve", {}).get("vulnerabilities", {})
    exploit_data = snapshot.values.get("vuln_map", {}).get("found_exploits", {})

    # We count how many targets have been processed
    vuln_count = sum(len(v) for v in vuln_data.values()) if vuln_data else 0
    exploit_count = sum(len(e) for e in exploit_data.values()) if exploit_data else 0

    return {
        "thread_id": thread_id,
        "current_node": snapshot.next[0] if snapshot.next else "FINISH",
        "is_paused": len(snapshot.next) > 0,
        "stats": {
            "hosts_scanned": len(recon_data.get("scanned_hosts", [])),
            "vulnerabilities_found": vuln_count,
            "exploits_available": exploit_count
        },
        "target": snapshot.values.get("user_target", "Unknown"),
        "last_update": snapshot.metadata.get("step") if snapshot.metadata else 0
    }

@app.post("/fork")
async def fork_audit(source_thread_id: str, new_thread_id: str):
    """
    Clones the state of an existing thread into a new one.
    This allows 'replaying' from a fixed point multiple times.
    """
    source_config: RunnableConfig = {"configurable": {"thread_id": source_thread_id}}
    snapshot = security_graph.get_state(source_config)
    
    if not snapshot.values:
        raise HTTPException(status_code=404, detail="Source thread not found")

    new_config: RunnableConfig = {"configurable": {"thread_id": new_thread_id}}
    
    security_graph.update_state(new_config, snapshot.values, as_node="supervisor")

    return {
        "status": "forked",
        "new_thread_id": new_thread_id,
        "message": f"New audit branched from {source_thread_id}. Ready to resume."
    }

@app.delete("/threads/{thread_id}")
async def delete_thread(thread_id: str):
    """
    Deletes all checkpoints and state for a specific thread_id.
    """
    if memory is None:
        raise HTTPException(status_code=500, detail="Database not initialized")

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM checkpoints WHERE thread_id = ?", (thread_id,))
        cursor.execute("DELETE FROM writes WHERE thread_id = ?", (thread_id,))
        
        deleted_count = cursor.rowcount
        
        conn.commit()
        conn.close()

        if deleted_count == 0:
            return {
                "status": "not_found",
                "message": f"No thread found with thread_id: {thread_id}"
            }

        logger.info(f"Thread {thread_id} wiped. Rows removed: {deleted_count}")
        
        return {
            "status": "deleted",
            "thread_id": thread_id,
            "rows_affected": deleted_count
        }
    except Exception as e:
        logger.error(f"Error deleting thread {thread_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.middleware("http")
async def audit_log_middleware(request: Request, call_next):
    # Capture relevant data
    start_time = time.time()
    host = request.client.host if request.client else "unknown"
    url = request.url.path
    user_agent = request.headers.get("user-agent", "none")

    # Proceed with the request
    response = await call_next(request)

    # Log the details
    process_time = (time.time() - start_time) * 1000
    if response.status_code == 404:
        logger.warning(
            f"[INTRUSION DETECTED] | IP: {host} | Path: {url} | "
            f"Agent: {user_agent} | Time: {process_time:.2f}ms"
        )
    return response

####################
# Helper functions #
####################
def check_deployment():
    logger.info("--- INITIALIZING DEPLOYMENT ---")
    status = True

    # Check Ollama
    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    try:
        response = requests.get(f"{ollama_url}/api/tags", timeout=5)
        if response.status_code == 200:
            logger.info(f"OLLAMA: Service active on {ollama_url}.")
        else:
            logger.warning(f"OLLAMA: Service answers but with error {response.status_code}.")
    except Exception as e:
        logger.error(f"OLLAMA: Unreachable. Check if Ollama is running.")
        status = False

    # Check environment
    try:
        import langgraph
        logger.info(f"ENVIRONMENT: LangGraph and dependencies correctly installed.")
    except ImportError:
        logger.error("ENVIRONMENT: Libraries missing. Check venv.")
        status = False

    logger.info("-------------------------------")
    if status:
        logger.info("DEPLOYED SUCCESSFULLY")
    else:
        logger.error("ERROR WHILE DEPLOYING")
    
    return status

async def handle_consultation(query, values, thread_id, is_finished):
    chat_model = get_model()
    compact_context = get_minimal_toon_context(values)
    status_text = "COMPLETED" if is_finished else "PAUSED"
    
    system_prompt = (
        f"You are a Cybersecurity Analyst. The audit is {status_text}.\n"
        "Answer the user's questions. If the user asks for details on a CVE, "
        "refer to the vulnerabilities table. Remind them to 'approve' or 'abort' if not finished."
        "Below is the data in TOON format (ip, port, product, etc.).\n"
        f"AUDIT DATA:\n{compact_context}"
    )
    
    answer = chat_model.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=query)
    ])
    
    return {
        "response": answer.content,
        "status": "consultation",
        "thread_id": thread_id
    }

async def start_fresh_audit(query, config, thread_id):
    initial_state: AgentState = {
        "user_target": "",
        "messages": [HumanMessage(content=query)],
        "next_step": "supervisor",
        "recon": {},
        "cve": {},
        "vuln_map": {},
        "exploit": {},
    }
    result = security_graph.invoke(initial_state, config=config)
    return format_graph_response(result, config, thread_id)

def format_graph_response(result, config, thread_id):
    final_snapshot = security_graph.get_state(config)
    if final_snapshot.next:
        return {"response": "Audit paused. Ready for your 'approve'.", "status": "paused", "thread_id": thread_id}
    return {"response": result["messages"][-1].content, "status": "success", "thread_id": thread_id}

##################
# Initialization #
##################
if __name__ == "__main__":
    if not check_deployment():
        sys.exit(1)
    logger.info("Starting Server on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)