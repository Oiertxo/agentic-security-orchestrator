# main.py
import os
import sys
import requests
from dotenv import load_dotenv

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

if __name__ == "__main__":
    if check_deployment():
        print("Waiting orders...")