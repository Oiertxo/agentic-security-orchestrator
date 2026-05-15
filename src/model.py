import os

from dotenv import load_dotenv
from langchain_ollama import ChatOllama

load_dotenv()

llm = ChatOllama(
    model=os.getenv("MODEL_NAME", "qwen2.5:7b"),
    temperature=0,
    base_url=os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434"),
    format="json",
    num_ctx=32768,
    num_gpu=-1,
    repeat_penalty=1.2,
)


def get_model():
    return llm
