from langchain_ollama import ChatOllama
import os
from dotenv import load_dotenv

load_dotenv()

llm = ChatOllama(
    model = os.getenv("MODEL_NAME", "qwen3:14b"),
    temperature = 0,
    base_url = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
)

def get_model():
    return llm