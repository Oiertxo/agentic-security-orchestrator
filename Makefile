.DEFAULT_GOAL := help
COMPOSE_FILES = -f compose.core.yml -f compose.targets.yml -f compose.monitoring.yml

help:
	@echo ""
	@echo "Available commands:"
	@echo ""
	@echo "  make core      Start core services (orchestrator + kali-engine)"
	@echo "  make lab       Start core + vulnerable targets"
	@echo "  make full      Start core + targets + monitoring"
	@echo "  make down      Stop running containers"
	@echo "  make clean     Stop and remove containers, networks and volumes"
	@echo ""

core:
	docker compose -f compose.core.yml up

lab:
	docker compose -f compose.core.yml -f compose.targets.yml up

full:
	docker compose $(COMPOSE_FILES) up

stop:
	docker compose $(COMPOSE_FILES) stop

down:
	docker compose $(COMPOSE_FILES) down

clean:
	docker compose $(COMPOSE_FILES) down -v --remove-orphans