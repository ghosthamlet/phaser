FROM golang:1.11-alpine AS builder

ARG CI_JOB_TOKEN

RUN apk update && apk add git ca-certificates make

WORKDIR /phaser
COPY . ./
RUN make static

####################################################################################################
## Image
####################################################################################################

FROM debian:9

RUN useradd -ms /bin/bash bloom
COPY --from=builder /phaser/dist/phaser /phaser/phaser
# copy assets
COPY assets /phaser/assets

# install dependencies
RUN echo "deb http://deb.debian.org/debian unstable main" >> /etc/apt/sources.list
RUN apt update -y && apt dist-upgrade -y && apt upgrade -y
RUN apt install -y  python3 python3-pip \
    dnsutils whois \
    ca-certificates libssl-dev
RUN apt -t unstable install -y sqlmap


USER bloom
# used for python binaries
ENV PATH="${PATH}:/home/bloom/.local/bin"

# install dependencies in userland
RUN pip3 install --upgrade -U sslyze dnspython

WORKDIR /phaser

CMD ["./phaser", "worker"]
