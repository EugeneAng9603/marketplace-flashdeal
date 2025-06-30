SERVICES := flashdeal stock user-auth order payment notification

.PHONY: up down rebuild test build clean

up:
	docker-compose up --build -d

down:
	docker-compose down

rebuild:
	docker-compose build --no-cache

build:
	@for svc in $(SERVICES); do \
		echo "Building $$svc..."; \
		docker build -t $$svc ./$$svc; \
	done

test:
	@echo "Running tests for all services..."
	@for svc in $(SERVICES); do \
		if [ -d "$$svc" ]; then \
			echo "Testing $$svc..."; \
			cd $$svc && go test ./... && cd ..; \
		fi \
	done

clean:
	docker system prune -f
