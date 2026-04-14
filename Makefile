# DefMon — Makefile
# Convenience targets for development, testing, and deployment.

.PHONY: dev stop test lint migrate bootstrap-admin clean logs

# Start full stack in development mode (hot-reload)
dev:
	docker compose up --build

# Start in detached mode
up:
	docker compose up --build -d

# Stop all services
stop:
	docker compose down

# Stop and remove volumes (clean database)
clean:
	docker compose down -v

# Run database migrations inside the running API container
migrate:
	docker compose exec defmon-api alembic upgrade head

# Run pytest with coverage report
test:
	docker compose exec defmon-api pytest --cov=defmon --cov-report=term-missing --cov-report=xml -v

# Run tests locally (without Docker)
test-local:
	pytest --cov=defmon --cov-report=term-missing -v

# Lint check with ruff + black
lint:
	docker compose exec defmon-api ruff check .
	docker compose exec defmon-api black --check .

# Lint and auto-fix
lint-fix:
	docker compose exec defmon-api ruff check --fix .
	docker compose exec defmon-api black .

# Bootstrap admin account without creating synthetic logs
bootstrap-admin:
	docker compose exec defmon-api python -m defmon.bootstrap --username admin --password admin

# View logs
logs:
	docker compose logs -f defmon-api

# View all service logs
logs-all:
	docker compose logs -f

# Rebuild without cache
rebuild:
	docker compose build --no-cache

# Show running services
status:
	docker compose ps
