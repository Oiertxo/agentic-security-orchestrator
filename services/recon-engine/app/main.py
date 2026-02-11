from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import subprocess, re

app = FastAPI(title="Recon Engine", version="1.0.0")

ALLOWED_TOOLS = {"nmap", "dig"}
ALLOWED_NMAP_FLAGS = {"-sV", "-sT", "-Pn", "-O"}
LAB_CIDR_REGEX = r"^192\.168\.1\.\d{1,3}$"

class ReconRequest(BaseModel):
    tool: str = Field(..., description="nmap | dig")
    target: str = Field(..., description="Lab IP")
    options: list[str] = Field(default=[])

def ensure_lab_target(target: str):
    if not re.match(LAB_CIDR_REGEX, target):
        raise HTTPException(status_code=400, detail="Target outside lab range")

def ensure_nmap_options(options: list[str]):
    for opt in options:
        if opt not in ALLOWED_NMAP_FLAGS:
            raise HTTPException(status_code=400, detail=f"Disallowed nmap option: {opt}")

@app.post("/run")
def run(req: ReconRequest):
    if req.tool not in ALLOWED_TOOLS:
        raise HTTPException(status_code=400, detail="Tool not allowed")
    ensure_lab_target(req.target)

    if req.tool == "nmap":
        ensure_nmap_options(req.options)
        cmd = ["nmap"] + req.options + ["-oX", "-", req.target]
    elif req.tool == "dig":
        cmd = ["dig", req.target, "ANY"]
    else:
        raise HTTPException(status_code=400, detail="Invalid tool")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "tool": req.tool,
        "target": req.target,
        "options": req.options,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }

@app.post("/run_mock")
def run_mock(req: ReconRequest):
    return {
        "tool": req.tool,
        "target": req.target,
        "options": req.options,
        "stdout": "Found open port 22 with no password necessary on 192.168.1.13",
        "stderr": "",
        "returncode": 0,
    }