import json
import subprocess
from pathlib import Path

# --- CONFIG ---
VULHUB_DIR = Path("../../../vulhub")
STATE_FILE = Path("state.json")

EXCLUDED_DIRS = {".github", ".claude"}
# ----------------


def list_services():
    if not VULHUB_DIR.exists():
        raise FileNotFoundError("vulhub directory not found")

    services = []
    for p in VULHUB_DIR.iterdir():
        if p.is_dir() and p.name not in EXCLUDED_DIRS and not p.name.startswith("."):
            services.append(p.name)

    return sorted(services)  # stable, reproducible order


def load_state():
    if not STATE_FILE.exists():
        return {"last_index": 0}
    return json.loads(STATE_FILE.read_text())


def save_state(state):
    STATE_FILE.write_text(json.dumps(state, indent=2))


def lift_service(service):
    compose_file = VULHUB_DIR / service / "docker-compose.yml"
    if not compose_file.exists():
        print(f"docker-compose.yml not found for {service}")
        return False

    print(f"\nStarting service: {service}")
    try:
        subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "up", "-d"],
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        print(f"Error while starting {service}")
        return False


def main():
    services = list_services()
    state = load_state()

    idx = state.get("last_index", 0)

    if idx >= len(services):
        print("All services already started.")
        return

    service = services[idx]

    print(f"\n=== Service {idx + 1} / {len(services)} ===")
    lift_service(service)

    # move to next service
    state["last_index"] = idx + 1
    save_state(state)

    print(f"\nFinished. Next service index: {state['last_index']}")


if __name__ == "__main__":
    main()
