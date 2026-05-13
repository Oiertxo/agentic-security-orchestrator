import os

import yaml

ATTACK_NET = "attack_net"
SKIP_DIRS = {".git", ".github", ".claude"}


def should_skip(path: str) -> bool:
    return any(part in SKIP_DIRS for part in path.split(os.sep))


def patch_compose(compose_path: str):
    with open(compose_path, "r") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict) or "services" not in data:
        return False

    # --- Patch each service ---
    for svc_name, svc in data["services"].items():
        if not isinstance(svc, dict):
            continue

        nets = svc.get("networks")

        # Normalize networks to list
        if nets is None:
            nets = []
        elif isinstance(nets, dict):
            nets = list(nets.keys())
        elif not isinstance(nets, list):
            nets = []

        if ATTACK_NET not in nets:
            nets.append(ATTACK_NET)

        svc["networks"] = nets

    # --- Patch top-level networks ---
    networks = data.get("networks", {})
    if ATTACK_NET not in networks:
        networks[ATTACK_NET] = {"external": True}
    data["networks"] = networks

    with open(compose_path, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)

    return True


def main():
    patched = 0

    for root, dirs, files in os.walk("./containers"):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        if "docker-compose.yml" in files or "docker-compose.yaml" in files:
            for name in ("docker-compose.yml", "docker-compose.yaml"):
                if name in files:
                    path = os.path.join(root, name)
                    if should_skip(path):
                        continue
                    try:
                        if patch_compose(path):
                            patched += 1
                            print(f"[OK] patched {path}")
                    except Exception as e:
                        print(f"[ERR] {path}: {e}")

    print(f"\nDone. Patched {patched} docker-compose files.")


if __name__ == "__main__":
    main()
