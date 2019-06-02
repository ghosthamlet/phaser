.PHONY: build clean re dev test build_static release
.PHONY: docker_login docker_build docker_release docker_push docker_dev

DIST_DIR = dist
NAME := $(shell cat Cargo.toml | grep "^name\s=" | cut -d '"' -f2)
VERSION := $(shell cat Cargo.toml | grep "^version\s=" | cut -d '"' -f2)
DOCKER_IMAGE = registry.gitlab.com/bloom42/$(NAME)
COMMIT = $(shell git rev-parse HEAD)

all: build

build:
	mkdir -p $(DIST_DIR)
	cargo build --release
	cp target/release/$(NAME) $(DIST_DIR)/$(NAME)
	cp -r assets $(DIST_DIR)/

build_static:
	mkdir -p $(DIST_DIR)
	cargo build --release --target=x86_64-unknown-linux-musl
	cp target/x86_64-unknown-linux-musl/release/$(NAME) $(DIST_DIR)/$(NAME)
	cp -r assets $(DIST_DIR)/

dev:
	cargo watch -x 'run -- worker'

clean:
	rm -rf $(DIST_DIR) target/

re: clean build

test:
	cargo test

lint:
	cargo +nightly fmt
	cargo clippy

audit:
	cargo audit

release:
	git tag v$(VERSION)
	git push origin v$(VERSION)

crates_login:
	cargo login ${CRATES_TOKEN}

crates_publish:
	cargo publish



docker_build:
	docker build -t $(DOCKER_IMAGE):latest .
	docker tag $(DOCKER_IMAGE):latest $(DOCKER_IMAGE):$(VERSION)

docker_login:
	docker login -u gitlab-ci-token -p ${CI_JOB_TOKEN} ${CI_REGISTRY}

docker_release:
	docker push $(DOCKER_IMAGE):$(VERSION)
	docker push $(DOCKER_IMAGE):latest

docker_dev:
	docker build -t $(DOCKER_IMAGE)_dev:latest -f dev.Dockerfile .
