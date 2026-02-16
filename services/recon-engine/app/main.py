from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import subprocess, ipaddress

app = FastAPI(title="Recon Engine", version="1.0.0")

ALLOWED_TOOLS = {"nmap", "dig"}
ALLOWED_NMAP_FLAGS = {"-sS", "-sV"}
LAB_NETWORK = ipaddress.IPv4Network("10.255.255.0/24")

class ReconRequest(BaseModel):
    tool: str = Field(..., description="nmap | dig")
    target: str = Field(..., description="Lab IP")
    options: list[str] = Field(default=[])

def ensure_lab_target(target: str):
    try:
        # Accept both single IPs and CIDR networks
        if "/" in target:
            net = ipaddress.IPv4Network(target, strict=False)
            
            if net.subnet_of(LAB_NETWORK):
                return
        else:
            ip = ipaddress.ip_address(target)
            if ip in LAB_NETWORK:
                return
    except ValueError:
        raise HTTPException(400, "Invalid IP or CIDR format")

    raise HTTPException(400, "Target outside lab range")

def ensure_nmap_options(options: list[str]):
    for opt in options:
        if opt not in ALLOWED_NMAP_FLAGS:
            # raise HTTPException(status_code=400, detail=f"Disallowed nmap option: {opt}")
            x=1

@app.post("/run")
def run(req: ReconRequest):
    if req.tool not in ALLOWED_TOOLS:
        raise HTTPException(status_code=400, detail="Tool not allowed")
    ensure_lab_target(req.target)

    if req.tool == "nmap":
        ensure_nmap_options(req.options)
        cmd = ["nmap"] + req.options + ["-n", "-Pn", "--max-retries", "1", "--host-timeout", "30s", "-T4", "-oX", "-", req.target]
    elif req.tool == "dig":
        cmd = ["dig", req.target, "ANY"]
    else:
        raise HTTPException(status_code=400, detail="Invalid tool")

    try:
        print(f"RECON CONTAINER DEBUG Command: {cmd}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
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
        "stdout": "Found open port 22 with no password necessary on 10.255.255.4",
        "stderr": "",
        "returncode": 0,
    }