from langchain_ollama import ChatOllama
import os
from dotenv import load_dotenv

load_dotenv()

llm = ChatOllama(
    model = os.getenv("MODEL_NAME", "hermes3"),
    temperature = 0,
    base_url = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434"),
    num_ctx=16384,
    num_gpu=-1,
    repeat_penalty=1.2
)

def get_model():
    return llm