import os

def load_prompt(filename: str) -> str:
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    prompt_path = os.path.join(base_path, "src/prompts", filename)
    
    with open(prompt_path, "r", encoding="utf-8") as f:
        return f.read().strip()