import os, sys, requests, uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from langchain_core.messages import HumanMessage
from src.graph import compile_workflow
from src.state import AgentState
from src.logger import logger
from langfuse.langchain import CallbackHandler

load_dotenv()

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

app = FastAPI(
    title="Agentic Security Orchestrator",
    description="API for the LangGraph Security Agent System",
    version="0.1.0"
)

langfuse_handler = CallbackHandler()

# Compile the Graph once at startup
try:
    security_graph = compile_workflow()
except Exception as e:
    logger.error(f"CRITICAL: Failed to compile graph: {e}")
    sys.exit(1)

# Define user request
class UserRequest(BaseModel):
    query: str
    thread_id: str = "default_thread"

# Define the API Endpoint
@app.post("/chat")
async def chat_endpoint(request: UserRequest):
    print(f"Received query: {request.query}")

    initial_state: AgentState = {
        "user_target": "",
        "messages": [HumanMessage(content=request.query)],
        "next_step": "supervisor",
        "recon": {},
        "exploit": {},
    }

    try:
        result = security_graph.invoke(initial_state, config={"callbacks": [langfuse_handler]})

        history = [f"{type(m).__name__}: {m.content[:30]}" for m in result["messages"]]
        
        final_message = result["messages"][-1].content
        
        logger.info(f"[MAIN] Sending response: {final_message}")
        return {
            "response": final_message,
            "history": history,
            "status": "success"
        }

    except Exception as e:
        logger.error(f"Error executing graph: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    if not check_deployment():
        sys.exit(1)
    logger.info("Starting Server on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)