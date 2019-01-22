.PHONY: build clean re dev test static docker docker_release release docker_push

NAME = $(shell cat version/version.go| grep "\sName" | cut -d '"' -f2)
DIST_DIR = dist
VERSION := $(shell cat version/version.go| grep "\sVersion" | cut -d '"' -f2)
DOCKER_IMAGE = "registry.gitlab.com/bloom42/phaser"
COMMIT = $(shell git rev-parse HEAD)


build:
	go build -o $(DIST_DIR)/$(NAME)

dev:
	go run main.go worker

clean:
	rm -rf $(DIST_DIR)

re: clean build

test:
	go vet ./...
	go test -v -race ./...

static:
	CGO_ENABLED=0 go build -a -installsuffix cgo -ldflags="-w -s" -o $(DIST_DIR)/$(NAME)

release:
	git tag v$(VERSION)
	git push origin v$(VERSION)

docker:
	docker build -t $(DOCKER_IMAGE):latest --build-arg CI_JOB_TOKEN=$(CI_JOB_TOKEN) .

docker_push:
	docker push $(DOCKER_IMAGE):latest

docker_release:
	docker pull $(DOCKER_IMAGE):latest
	docker tag $(DOCKER_IMAGE):latest $(DOCKER_IMAGE):$(VERSION)
	docker push $(DOCKER_IMAGE):$(VERSION)
