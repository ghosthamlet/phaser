.PHONY: build clean re dev test static docker docker_release release docker_push

NAME = $(shell cat version/version.go| grep "\sName" | cut -d '"' -f2)
DIST_DIR = dist
VERSION := $(shell cat version/version.go| grep "\sVersion" | cut -d '"' -f2)
DOCKER_IMAGE = "quay.io/bloom42/$(NAME)"
COMMIT = $(shell git rev-parse HEAD)


build:
	go build -o $(DIST_DIR)/$(NAME)
	cp -r assets $(DIST_DIR)/

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

docker:
	docker build -t $(DOCKER_IMAGE):latest .
	docker tag $(DOCKER_IMAGE):latest $(DOCKER_IMAGE):$(VERSION)

release:
	git tag v$(VERSION)
	git push origin v$(VERSION)

docker_push:
	docker push $(DOCKER_IMAGE):latest

docker_release: docker
	docker push $(DOCKER_IMAGE):$(VERSION)
