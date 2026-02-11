import os, json
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

def load_prompt(filename: str) -> str:
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    prompt_path = os.path.join(base_path, "src/prompts", filename)
    
    with open(prompt_path, "r", encoding="utf-8") as f:
        return f.read().strip()
    
def parse_as_json(x):
    # Case 1: Already a dict
    if isinstance(x, dict):
        return x
    
    # Case 2: A list (maybe a single JSON object inside)
    if isinstance(x, list):
        # If it's a list with one dict → extract
        if len(x) == 1 and isinstance(x[0], dict):
            return x[0]
        raise ValueError(f"Cannot parse list as JSON: {x}")

    # Case 3: It's an LLM message object
    if hasattr(x, "content"):
        return parse_as_json(x.content)

    # Case 4: It's a string containing JSON
    if isinstance(x, str):
        try:
            return json.loads(x)
        except Exception as e:
            raise ValueError(f"String is not valid JSON: {x[:200]}") from e

    # Fallback
    raise ValueError(f"Unsupported JSON input type: {type(x)}")


def get_clean_content(messages):
    clean_content = []
    for m in messages:
        content = str(m.content)
        if isinstance(m, HumanMessage):
            clean_content.append(HumanMessage(content=content))
        elif isinstance(m, AIMessage):
            clean_content.append(AIMessage(content=content))
        elif isinstance(m, SystemMessage):
            clean_content.append(SystemMessage(content=content))
    return clean_content