import json
import subprocess
from pathlib import Path

# --- CONFIG ---
BASE_DIR = Path(__file__).resolve().parent
VULHUB_DIR = (BASE_DIR / "../../../vulhub").resolve()
STATE_FILE = (BASE_DIR / "state.json").resolve()
EXCLUDED_DIRS = {".github", ".claude"}
# ----------------


def list_environments():

    print("VULHUB_DIR (raw):", VULHUB_DIR)
    print("VULHUB_DIR exists:", VULHUB_DIR.exists())
    print("VULHUB_DIR resolved:", VULHUB_DIR.resolve())

    if not VULHUB_DIR.exists():
        raise FileNotFoundError("vulhub directory not found")

    envs = []

    for root in VULHUB_DIR.rglob("docker-compose.yml"):
        env_dir = root.parent

        if any(part in EXCLUDED_DIRS for part in env_dir.parts):
            continue
        if any(part.startswith(".") for part in env_dir.parts):
            continue

        envs.append(env_dir)

    return sorted(envs, key=lambda p: str(p))


def load_state():
    if not STATE_FILE.exists():
        return {"last_index": 0}
    return json.loads(STATE_FILE.read_text())


def save_state(state):
    STATE_FILE.write_text(json.dumps(state, indent=2))


def create_environment(env_dir: Path):
    compose_file = env_dir / "docker-compose.yml"

    print(f"\nStarting environment: {env_dir}")
    try:
        subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "up", "-d"],
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        print(f"Error while starting {env_dir}")
        return False


def stop_environment(env_dir: Path):
    compose_file = env_dir / "docker-compose.yml"

    if not compose_file.exists():
        print(f"No docker-compose.yml found to stop in {env_dir}")
        return False

    print(f"\nStopping environment: {env_dir}")
    try:
        subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "down"],
            check=True,
        )
        return True
    except subprocess.CalledProcessError:
        print(f"Error while stopping {env_dir}")
        return False


def main():
    envs = list_environments()
    print(envs)

    if not envs:
        print("No environments found.")
        return

    state = load_state()
    idx = state.get("last_index", 0)

    if idx >= len(envs):
        print("All environments already processed.")
        return

    # Stop previous environment if any
    if idx > 0:
        prev_env = envs[idx - 1]
        stop_environment(prev_env)

    # Start current environment
    current_env = envs[idx]
    print(f"\n=== Environment {idx + 1} / {len(envs)} ===")
    create_environment(current_env)

    state["last_index"] = idx + 1
    save_state(state)

    print(f"\nDone. Next environment index: {state['last_index'] + 1}")


if __name__ == "__main__":
    main()
