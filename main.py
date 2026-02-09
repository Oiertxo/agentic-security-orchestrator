# main.py
import os, sys, requests, uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from langchain_core.messages import HumanMessage
from src.graph import compile_workflow
from src.state import AgentState

load_dotenv()

def check_deployment():
    print("--- INITIALIZING DEPLOYMENT ---")
    status = True

    # Check GPU
    status = check_gpu()

    # Check Ollama
    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    try:
        response = requests.get(f"{ollama_url}/api/tags", timeout=5)
        if response.status_code == 200:
            print(f"OLLAMA: Service active on {ollama_url}.")
        else:
            print(f"OLLAMA: Service answers but with error {response.status_code}.")
    except Exception as e:
        print(f"OLLAMA: Unreachable. Check if Ollama is running.")
        status = False

    # Check environment
    try:
        import langgraph
        print(f"ENVIRONMENT: LangGraph and dependencies correctly installed.")
    except ImportError:
        print("ENVIRONMENT: Libraries missing. Check venv.")
        status = False

    print("-------------------------------")
    if status:
        print("DEPLOYED SUCCESSFULLY")
    else:
        print("ERROR WHILE DEPLOYING")
    
    return status

def check_gpu():
    try:
        import pynvml
        pynvml.nvmlInit()
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        info = pynvml.nvmlDeviceGetMemoryInfo(handle)
        name = pynvml.nvmlDeviceGetName(handle)
        
        print(f"GPU: {name}")
        print(f"VRAM: {int(info.total) / 1024**2:.0f} MB")
        pynvml.nvmlShutdown()
        return True
    except Exception as e:
        print(f"GPU not detected: {e}")
        return False
    
app = FastAPI(
    title="Agentic Security Orchestrator",
    description="API for the LangGraph Security Agent System",
    version="0.1.0"
)

# Compile the Graph once at startup
try:
    security_graph = compile_workflow()
except Exception as e:
    print(f"CRITICAL: Failed to compile graph: {e}")
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
        "messages": [HumanMessage(content=request.query)],
        "next_step": "supervisor" # Initialize with a default value
    }

    try:
        result = security_graph.invoke(initial_state)

        history = [f"{type(m).__name__}: {m.content[:30]}" for m in result["messages"]]
        
        final_message = result["messages"][-1].content
        
        print(f"Sending response: {final_message[:50]}...")
        return {
            "response": final_message,
            "history": history,
            "status": "success"
        }

    except Exception as e:
        print(f"Error executing graph: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    if not check_deployment():
        sys.exit(1)
    print("Starting Server on port 8000...")
    uvicorn.run(app, host="0.0.0.0", port=8000)