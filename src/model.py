from langchain_ollama import ChatOllama
import os
from dotenv import load_dotenv

load_dotenv()

llm = ChatOllama(
    model="hermes3",
    temperature=0,
    base_url="http://localhost:11434"
)

def get_model():
    return llm