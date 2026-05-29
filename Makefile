.PHONY: run build test test-race race lint docker-up docker-down migrate dev setup-db fix-docker-dns

APP_NAME=auth-service
MAIN_PATH=./cmd/api

run:
	go run $(MAIN_PATH)

build:
	CGO_ENABLED=0 go build -o bin/$(APP_NAME) $(MAIN_PATH)

test:
	go test ./... -count=1 -coverprofile=coverage.out

# -race requires CGO and a C compiler (gcc).
test-race:
	@command -v gcc >/dev/null 2>&1 || { \
		echo "error: gcc not found — install build tools first:" >&2; \
		echo "  sudo apt-get update && sudo apt-get install -y build-essential" >&2; \
		exit 1; \
	}
	CGO_ENABLED=1 go test ./... -race -count=1 -coverprofile=coverage.out

race: test-race

test-e2e:
	BASE_URL=$${BASE_URL:-http://localhost:$${AUTH_HTTP_PORT:-8081}} bash scripts/e2e.sh

lint:
	golangci-lint run ./...

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f api

migrate-up:
	migrate -path migrations -database "postgres://auth:auth@localhost:5432/auth?sslmode=disable" up

migrate-down:
	migrate -path migrations -database "$${DATABASE_URL}" down 1

# Desenvolvimento local sem Docker (postgres + redis no sistema)
setup-db:
	bash scripts/setup-local-db.sh

dev: migrate-up run

fix-docker-dns:
	bash scripts/fix-docker-dns.sh
