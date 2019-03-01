FROM rust:1.33-stretch AS builder

RUN apt update && apt install -y make
RUN rustup target install x86_64-unknown-linux-musl

WORKDIR /phaser
COPY ./ ./
RUN make build_static

####################################################################################################
## Image
####################################################################################################

FROM debian:9

RUN useradd -ms /bin/bash bloom

RUN mkdir -p /home/bloom/.local/bin && chown -R bloom:bloom /home/bloom/.local && chmod 700 /home/bloom/.local/bin
RUN mkdir /phaser && chown -R bloom:bloom /phaser && chmod 700 /phaser

# Add phaser to path
COPY --from=builder /phaser/dist/phaser /home/bloom/.local/bin/phaser

# copy assets
COPY assets /phaser/assets

# install dependencies
RUN echo "deb http://deb.debian.org/debian unstable main" >> /etc/apt/sources.list
RUN apt update -y && apt dist-upgrade -y && apt upgrade -y
RUN apt install -y  python3 python3-pip \
    dnsutils whois \
    ca-certificates libssl-dev nmap
RUN apt -t unstable install -y sqlmap


USER bloom
# used for python binaries
ENV PATH="${PATH}:/home/bloom/.local/bin"

# install dependencies in userland
RUN pip3 install --upgrade -U sslyze dnspython

WORKDIR /phaser

CMD ["phaser", "worker"]
