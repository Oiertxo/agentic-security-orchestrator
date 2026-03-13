import os, sys, requests, uvicorn, aiosqlite, time, json, asyncio
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Optional
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableConfig
from src.graph import compile_workflow
from src.model import get_model
from src.utils.toon_formatter import get_minimal_toon_context
from src.logger import logger
from langfuse.langchain import CallbackHandler
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.graph.state import CompiledStateGraph
from contextlib import asynccontextmanager

load_dotenv()

DB_PATH = "/app/data/database/checkpoints.db"
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

memory: Optional[AsyncSqliteSaver] = None
security_graph: Optional[CompiledStateGraph] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global memory, security_graph
    try:
        async with AsyncSqliteSaver.from_conn_string(DB_PATH) as saver:
            memory = saver
            security_graph = compile_workflow(checkpointer=memory)
            logger.info("[MAIN] DB and Graph ready")
            yield
    finally:
        logger.info("[MAIN] DB connection closed")

app = FastAPI(
    title="Agentic Security Orchestrator",
    description="API for the LangGraph Security Agent System",
    version="0.1.0",
    lifespan=lifespan
)

langfuse_handler = CallbackHandler()

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
        "configurable": {"thread_id": thread_id, "start_time": str(time.time())},
        "callbacks": [langfuse_handler]
    }

    async def event_generator():
        try:
            yield f"data: {json.dumps({'token': 'Initiating orchestrator\n', 'type': 'status'})}\n\n"
            # Type Guard
            if security_graph is None:
                logger.error("[MAIN] Security graph was not initialized during lifespan.")
                yield f"data: {json.dumps({'error': 'System not ready'})}\n\n"
                return

            snapshot = await security_graph.aget_state(config)

            # Fresh start
            if request.start_new:
                await delete_thread(thread_id)
                async for chunk in start_fresh_audit_stream(request.query, config, thread_id):
                    yield chunk
                return

            # Control commands
            is_control_command = any(cmd in query for cmd in ["approve", "abort"])
            if is_control_command and not snapshot.next:
                if not snapshot.values:
                    yield f"data: {json.dumps({'error': 'Thread not found', 'status': 404})}\n\n"
                    return
                yield f"data: {json.dumps({'error': 'Thread already finished'})}\n\n"
                return

            if snapshot.values:
                if snapshot.next:
                    if "approve" in query:
                        async for chunk in run_graph_stream(None, config, thread_id):
                            yield chunk
                    elif "abort" in query:
                        await security_graph.aupdate_state(config, {"next_step": "report"})
                        async for chunk in run_graph_stream(None, config, thread_id):
                            yield chunk
                    else:
                        async for chunk in handle_consultation_stream(request.query, snapshot.values, thread_id, False):
                            yield chunk
                else:
                    # Post-Audit Analysis
                    async for chunk in handle_consultation_stream(request.query, snapshot.values, thread_id, True):
                        yield chunk
            else:
                # Default: new thread
                async for chunk in start_fresh_audit_stream(request.query, config, thread_id):
                    yield chunk

        except Exception as e:
            logger.error(f"Streaming Error: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        finally:
            await asyncio.sleep(0.1)

    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }

    return StreamingResponse(event_generator(), headers=headers)

@app.get("/threads")
async def list_threads():
    """
    Lists all unique thread IDs stored in the SQLite database.
    This helps the user see previous audits.
    """
    if memory is None:
        logger.error(f"[MAIN] Database not initialized")
        raise HTTPException(status_code=500, detail="Database not initialized")

    try:
        threads = []
        async for checkpoint in memory.alist(config=None):
            config = checkpoint.config
            if config and "configurable" in config:
                t_id = config["configurable"].get("thread_id")
                if isinstance(t_id, str) and t_id not in threads:
                    threads.append(t_id)
        
        return {
            "total_threads": len(threads),
            "threads": threads,
        }
    except Exception as e:
        logger.error(f"[MAIN] Error listing threads: {e}")
        raise HTTPException(status_code=500, detail="Could not retrieve threads.")
    
@app.get("/threads/{thread_id}")
async def get_detailed_status(thread_id: str):
    """
    Returns the current progress, identified vulnerabilities, 
    and next steps for a specific audit thread.
    """
    if security_graph is None:
        logger.error(f"[MAIN] Security graph not initialized")
        raise HTTPException(status_code=500, detail="Security graph not initialized")

    config: RunnableConfig = {"configurable": {"thread_id": thread_id}}
    
    try:
        snapshot = await security_graph.aget_state(config)
        
        if not snapshot.values:
            raise HTTPException(status_code=404, detail="Thread not found.")

        recon_data = snapshot.values.get("recon", {})
        vuln_data = snapshot.values.get("cve", {}).get("vulnerabilities", {})
        exploit_data = snapshot.values.get("vuln_map", {}).get("found_exploits", {})

        # Telemetry
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
    except Exception as e:
        logger.error(f"[MAIN] Error retrieving status for thread {thread_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal error retrieving thread state")

@app.post("/fork")
async def fork_audit(source_thread_id: str, new_thread_id: str):
    """
    Clones the state of an existing thread into a new one.
    This allows 'replaying' from a fixed point multiple times.
    """
    if security_graph is None:
        logger.error(f"[MAIN] Security graph not initialized")
        raise HTTPException(status_code=500, detail="Security graph not initialized")

    source_config: RunnableConfig = {"configurable": {"thread_id": source_thread_id}}
    
    try:
        snapshot = await security_graph.aget_state(source_config)
        
        if not snapshot.values:
            raise HTTPException(status_code=404, detail="Source thread not found")

        new_config: RunnableConfig = {"configurable": {"thread_id": new_thread_id}}
        
        await security_graph.aupdate_state(
            new_config, 
            snapshot.values, 
            as_node="supervisor"
        )

        return {
            "status": "forked",
            "new_thread_id": new_thread_id,
            "message": f"New audit branched from {source_thread_id}. Ready to resume."
        }
    except Exception as e:
        logger.error(f"[MAIN] Error forking thread {source_thread_id} to {new_thread_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal error during thread forking")

@app.delete("/threads/{thread_id}")
async def delete_thread(thread_id: str):
    """
    Deletes all checkpoints and state for a specific thread_id.
    """
    if memory is None:
        logger.error("Database connection not established.")
        raise HTTPException(status_code=500, detail="Database not initialized")

    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("DELETE FROM checkpoints WHERE thread_id = ?", (thread_id,))
            await db.execute("DELETE FROM writes WHERE thread_id = ?", (thread_id,))
            
            async with db.execute("SELECT changes()") as cursor:
                row = await cursor.fetchone()
                deleted_count = row[0] if row else 0
            
            await db.commit()

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

async def handle_consultation_stream(query, values, thread_id, is_finished):
    if security_graph is None:
        yield f"data: {json.dumps({'error': 'Graph not initialized'})}\n\n"
        return

    chat_model = get_model()
    compact_context = get_minimal_toon_context(values)
    status_text = "COMPLETED" if is_finished else "PAUSED"
    
    system_prompt = (
        f"You are a Cybersecurity Analyst. The audit is {status_text}.\n"
        "Answer the user's questions. If the user asks for details on a CVE, "
        "refer to the vulnerabilities table. Remind them to 'approve' or 'abort' if the audit is PAUSED."
        "Below is the data in TOON format (ip, port, product, etc.).\n"
        f"AUDIT DATA:\n{compact_context}"
    )

    async for chunk in chat_model.astream([
        SystemMessage(content=system_prompt),
        HumanMessage(content=query)
    ]):
        if chunk.content:
            yield f"data: {json.dumps({'token': chunk.content, 'type': 'content'})}\n\n"
    
    yield f"data: {json.dumps({'status': 'done'})}\n\n"

async def run_graph_stream(input_data, config, thread_id):
    if security_graph is None: return

    async for event in security_graph.astream_events(input_data, config=config, version="v2"):
        kind = event["event"]
        name = event["name"]
        metadata = event.get("metadata", {})
        node_name = metadata.get("langgraph_node")

        if kind == "on_chain_start" and node_name:
            yield f"data: {json.dumps({
                'node': node_name, 
                'type': 'status', 
                'event': 'start'
            })}\n\n"

        elif kind == "on_chain_end" and node_name:
            yield f"data: {json.dumps({
                'node': node_name, 
                'type': 'status', 
                'event': 'end'
            })}\n\n"

        elif kind == "on_chat_model_stream":
            data = event.get("data", {})
            chunk = data.get("chunk")
            
            if chunk and hasattr(chunk, "content"):
                content = chunk.content
                if content:
                    yield f"data: {json.dumps({'token': content, 'type': 'content'})}\n\n"

    final_state = await security_graph.aget_state(config)
    if not final_state.next:
        messages = final_state.values.get("messages", [])
        if messages:
            yield f"data: {json.dumps({'token': messages[-1].content, 'type': 'final_report'})}\n\n"

async def start_fresh_audit_stream(query, config, thread_id):
    initial_state = {
        "user_target": "",
        "messages": [HumanMessage(content=query)],
        "next_step": "supervisor",
        "recon": {},
        "cve": {},
        "vuln_map": {},
        "exploit": {},
    }
    async for chunk in run_graph_stream(initial_state, config, thread_id):
        yield chunk

async def format_graph_response(result, config, thread_id):
    if security_graph is None:
        return {"error": "Graph not initialized"}

    final_snapshot = await security_graph.aget_state(config)
    
    if final_snapshot.next:
        return {
            "response": "Audit paused. Ready for your 'approve'.", 
            "status": "paused", 
            "thread_id": thread_id
        }
    
    # El resultado del invoke asíncrono suele estar en el snapshot final
    last_message = final_snapshot.values["messages"][-1].content if final_snapshot.values.get("messages") else "No response"
    return {
        "response": last_message, 
        "status": "success", 
        "thread_id": thread_id
    }

##################
# Initialization #
##################
if __name__ == "__main__":
    if not check_deployment():
        sys.exit(1)
    logger.info("Starting Server on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)