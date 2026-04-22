.PHONY: build run dev test migrate-up migrate-down docker-up docker-down generate-key clean

GO := /opt/homebrew/bin/go
BINARY := aegis
DATABASE_URL ?= postgres://aegis:aegis@localhost:5432/aegis?sslmode=disable

build:
	$(GO) build -ldflags="-s -w" -o bin/$(BINARY) ./cmd/server

run: build
	./bin/$(BINARY)

dev:
	$(GO) run ./cmd/server

test:
	$(GO) test -v -race -count=1 ./...

migrate-up:
	$(GO) run -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest \
		-path migrations -database "$(DATABASE_URL)" up

migrate-down:
	$(GO) run -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest \
		-path migrations -database "$(DATABASE_URL)" down 1

migrate-create:
	$(GO) run -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest \
		create -ext sql -dir migrations -seq $(name)

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

generate-key:
	@openssl rand -base64 32

clean:
	rm -rf bin/

lint:
	golangci-lint run ./...

.DEFAULT_GOAL := build
