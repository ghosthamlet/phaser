.PHONY: build lint test audit docker docker_release docker_push release

NAME = $(shell cat src/info.rs  | grep NAME | cut -d'"' -f2)
DIST_DIR = target
VERSION := $(shell cat Cargo.toml | grep "version\s=" | cut -d '"' -f2)
DOCKER_IMAGE = registry.gitlab.com/bloom42/$(NAME)
COMMIT = $(shell git rev-parse HEAD)

all: build

$(NAME): build

build:
	cargo build --release

release:
	git tag v$(VERSION)
	git push origin v$(VERSION)

lint:
	cargo clippy

audit:
	cargo audit

test:
	cargo test

docker:
	docker build -t $(DOCKER_IMAGE):latest .

docker_push:
	docker push $(DOCKER_IMAGE):latest

docker_release: docker
	docker tag $(DOCKER_IMAGE):latest $(DOCKER_IMAGE):$(VERSION)
	docker push $(DOCKER_IMAGE):$(VERSION)
