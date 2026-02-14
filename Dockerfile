# https://dev.to/zakame/a-few-tips-for-perl-on-docker-and-kubernetes-29bg
# docker build -t myorg/myapp:dev .

FROM perl:5.42-slim

LABEL maintainer="bugre"
LABEL version="v0.3.1"
LABEL description="pcap2mpegts (pcap2ts) extracts a transport stream (TS) from a network capture pcap file (tcpdump / wireshark)."

WORKDIR /usr/src/app

# Install dependencies first (cached unless deps change)
RUN curl -L https://cpanmin.us | perl - App::cpanminus \
    && cpanm install Net::TcpDumpLog NetPacket::IP NetPacket::UDP Getopt::Long

COPY pcap2mpegts.pl /usr/src/app

ENTRYPOINT ["perl", "pcap2mpegts.pl"]
