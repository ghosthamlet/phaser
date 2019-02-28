FROM golang:1.11-stretch

RUN useradd -ms /bin/bash bloom

RUN mkdir /phaser && chown -R bloom:bloom /phaser && chmod 700 /phaser

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

CMD ["bash"]
