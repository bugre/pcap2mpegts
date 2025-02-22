# https://dev.to/zakame/a-few-tips-for-perl-on-docker-and-kubernetes-29bg
# docker build -t myorg/myapp:dev .\

FROM perl:5.41.8-slim

LABEL maintainer="bugre"
LABEL version="v0.3.0" description="Use pcap2mpegts to extract a transport stream (TS) from a network capture pcap file (tcpdump / wireshark)."

WORKDIR /usr/src/app
ADD pcap2mpegts.pl /usr/src/app

RUN curl -L http://cpanmin.us | perl - App::cpanminus
RUN cpanm install Net::TcpDumpLog NetPacket::IP NetPacket::UDP Getopt::Long
ENTRYPOINT ["perl", "pcap2mpegts.pl"]
