SHELL := /bin/bash

GO ?= go
DOCKER_COMPOSE ?= docker compose
GOCACHE ?= /tmp/loginvalidator-gocache
GOMODCACHE ?= $(HOME)/go/pkg/mod

.PHONY: test run demo-load up down

test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) test ./...

run:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) run .

demo-load:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) $(GO) run ./synthetic-producer

up:
	$(DOCKER_COMPOSE) up --build

down:
	$(DOCKER_COMPOSE) down
