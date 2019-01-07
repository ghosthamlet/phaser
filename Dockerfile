FROM rust:1.31.1-stretch AS builder

RUN apt update && apt install -y make

WORKDIR /phaser
COPY ./ ./
RUN make build

####################################################################################################
## Image
####################################################################################################

FROM debian:9

RUN useradd -ms /bin/bash bloom
COPY --from=builder /phaser/target/release/phaser /phaser/phaser
# copy assets
COPY assets /phaser/assets

# install dependencies
RUN echo "deb http://deb.debian.org/debian unstable main" >> /etc/apt/sources.list
RUN apt update -y && apt dist-upgrade -y && apt upgrade -y
RUN apt install -y  python3 python3-pip ca-certificates libssl-dev \
    dnsutils \
    nmap whois
RUN apt -t unstable install -y sqlmap


USER bloom
# used for python binaries
ENV PATH="${PATH}:/home/bloom/.local/bin"

# install dependencies in userland
RUN pip3 install --upgrade -U sslyze dnspython

WORKDIR /phaser

CMD ["./phaser", "worker"]
