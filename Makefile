.DEFAULT_GOAL := help
COMPOSE_FILES = -f compose.core.yml -f compose.targets.yml -f compose.monitoring.yml
ATTACK_NET = attack_net
ATTACK_SUBNET = 10.255.255.0/24
ATTACK_GATEWAY = 10.255.255.1

# --- DETECCIÓN DE SISTEMA OPERATIVO ---
ifeq ($(OS),Windows_NT)
    SHELL := cmd.exe
    PYTHON := python.exe
    DEV_NULL := NUL
    RM_NET_IGNORE := || exit 0
else
    SHELL := /bin/bash
    PYTHON := python
    DEV_NULL := /dev/null
    RM_NET_IGNORE := || true
endif

.PHONY: help core lab full stop down clean network remove-network next

help:
	@echo ""
	@echo "Available commands:"
	@echo ""
	@echo "  make core              Start core services"
	@echo "  make lab               Start core + vulnerable targets"
	@echo "  make full              Start core + targets + monitoring"
	@echo "  make down              Stop running containers"
	@echo "  make clean             Stop and remove containers, networks and volumes"
	@echo "  make network           Create Docker attack_net network"
	@echo "  make remove-network    Remove Docker attack_net network"
	@echo "  make next              Start next Vulhub service containers"
	@echo ""

core: network
	docker compose -f compose.core.yml up --build

lab: network
	docker compose -f compose.core.yml -f compose.targets.yml up --build

full: network
	docker compose $(COMPOSE_FILES) up --build

stop:
	docker compose $(COMPOSE_FILES) stop

down:
	docker compose $(COMPOSE_FILES) down
	$(MAKE) remove-network

clean:
	docker compose $(COMPOSE_FILES) down -v --remove-orphans
	$(MAKE) remove-network

network:
	@echo "[*] Ensuring attack network exists: $(ATTACK_NET)"
	@docker network inspect $(ATTACK_NET) > $(DEV_NULL) 2>&1 || docker network create \
			--driver bridge \
			--subnet $(ATTACK_SUBNET) \
			--gateway $(ATTACK_GATEWAY) \
			--attachable \
			$(ATTACK_NET)

remove-network:
	@echo "[*] Removing attack network: $(ATTACK_NET)"
	@docker network rm $(ATTACK_NET) > $(DEV_NULL) 2>&1 $(RM_NET_IGNORE)

next:
	$(PYTHON) ./services/vulhub_tests/create_services.py