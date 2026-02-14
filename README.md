---
name: pcap2mpegts
aliases: [pcap2ts]
description: "Convert PCAP network capture files (UDP multicast) to MPEG Transport Stream video files. Use case: troubleshoot multicast traffic, evaluate packet loss with tcpdump/Wireshark."
language: Perl
keywords: pcap, pcap2ts, mpeg-ts, transport stream, tcpdump, wireshark, multicast, udp, video extraction, broadcast
license: GPL-2.0
---

# pcap2mpegts (_aka_ pcap2ts)

**Extract MPEG-TS (Transport Stream) video from PCAP capture files** — Convert tcpdump/Wireshark UDP multicast captures to valid MPEG-TS files for analysis with dvb-inspector, tstools, tsduck, ffmpeg and/or similar tools.

## Keywords

`pcap` `pcap2ts` `mpeg-ts` `transport stream` `tcpdump` `wireshark` `multicast` `udp` `video extraction` `broadcast`

## Quick start (recommended)

Use Docker — no Perl or module installation required:

```bash
## with the .pcap file in the directory where you're executing this command, do...
docker run --rm -v $PWD:/inout bugre/pcap2mpegts --yes --logfile /inout/mycapture.pcap --outfile /inout/mycapture.ts
```

## Table of Contents

- [Quick start (recommended)](#quick-start-recommended)
- [What is this?](#what-is-this)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Command Line Options](#command-line-options)
- [How to Capture Data](#how-to-capture-data)
  - [Check if multicast is subscribed](#check-if-multicast-is-subscribed)
  - [Subscribe with socat](#subscribe-with-socat)
- [Docker Build](#docker-build)
- [FAQ](#faq)
- [Credits](#credits)

## What is this?

pcap2mpegts (also known as **pcap2ts**) is a Perl tool that reads PCAP files, extracts UDP multicast payloads, and writes them as valid MPEG-TS files — so you can analyze multicast traffic with video/audio tools instead of raw packet inspection.

I had the need to troubleshoot multicast traffic, and the closest way to the network card to capture the traffic to evaluate packet loss or damage is using tools like tcpdump, Wireshark or other PCAP capture options.

But the evaluation of the data stream on an MPEG (video/audio) level using tools like dvb-inspector, ffmpeg and others requires the data correctly formatted as MPEG Transport Stream.

If the PCAP file captured has multiple transport streams on different IP (group) or UDP ports, you must use `-p <dst_port>` and/or `-i <mcast_ip> -p <dst_port>` so that the extracted TS has only the selected MPEG audio/video.

## Prerequisites

**Option A (recommended):** Docker — no Perl or module installation needed. Just run the container.

**Option B:** Perl 5.x and modules (Net::TcpDumpLog, NetPacket::IP, NetPacket::UDP, Getopt::Long) — see [Installation](#installation) below.

## Usage Options

### 1. Docker (recommended — no Perl or modules to install)

```bash
docker run --rm -v $PWD:/inout bugre/pcap2mpegts \
      --yes                                      \
      --logfile /inout/mycapture.pcap            \
      --outfile /inout/mycapture.ts
```

### 2. Perl (pcap2mpegts.pl / pcap2ts.pl)

```bash
pcap2mpegts.pl -l <pcap_capture_file.pcap> -o <output_mpeg.ts>
```

With filtering (specific multicast group + port):

```bash
pcap2mpegts.pl -y -i 239.100.0.1 -p 2000 -l multi_ts_capture.pcap -o single-stream-output.ts
```

## Command Line Options

```
 -l|--logfile <file>        # input capture (PCAP) log file
 -o|--outfile <file>        # output transport stream file
 -y|--yes                   # **overwrite** the output file without confirmation.
 -p|--dest_port dest_port   # filter extraction by UDP Destination Port
 -i|--dest_ip dest_ip       # filter extraction by mcast group IP.
                              *MUST* also specify port if IP is specified
```

## How to Capture Data

You *must ensure* that your multicast group `239.100.0.1/port` (in this example) is already joined on the same server/NIC, so that the traffic is flowing on the *NIC* that you'll capture.

**Note:** If tcpdump does not receive any data, you probably aren't subscribed to the multicast. You'll have to manually subscribe first—see [Subscribe with socat](#subscribe-with-socat) below.

```bash
# specific multicast group (IP) and destination port on NIC eth0
tcpdump -nn -s0 -B 8192 -w mycapture.pcap -i eth0 host 239.100.0.1 and port 3456 and udp

# specific multicast group (IP) on NIC eth0
tcpdump -nn -s0 -B 8192 -w mycapture.pcap -i eth0 host 239.100.0.1 and udp

# all udp traffic seen on the NIC
tcpdump -nn -s0 -B 8192 -w mycapture.pcap -i eth0 udp
```

### Check if multicast is subscribed

To see which multicast groups your interfaces have joined:

```bash
# All multicast memberships
ip maddr show

# Only IPv4, for a specific interface
ip -4 maddr show dev eth0

# UDP sockets listening on multicast (ss is the modern netstat)
ss -apu
```

### Subscribe with socat

If no process has joined the multicast group yet, use `socat` to subscribe before running tcpdump. Replace `INTERFACE_IP` with the IP address of your capture interface (e.g. `192.168.1.100` for eth0). The socat process must stay running while you capture; run it in a separate terminal or in the background.

```bash
# Join multicast 239.100.0.1:3456 on interface with IP 192.168.1.100
sudo socat -u UDP4-RECV:3456,ip-add-membership=239.100.0.1:192.168.1.100,reuseaddr OPEN:/dev/null &

# Then capture with tcpdump (in another terminal)
tcpdump -nn -s0 -B 8192 -w mycapture.pcap -i eth0 host 239.100.0.1 and port 3456 and udp
```

For a different multicast group and port, change `3456` and `239.100.0.1` accordingly. Install socat if needed: `apt-get install socat` (Debian/Ubuntu), `yum install socat` (RHEL/CentOS), `brew install socat` (macOS).

## Installation (when using source + perl install.)

*NOT needed if you use Docker option(recommended).*

- Clone this repo or copy the `pcap2mpegts.pl` file to your system.
- You'll need Perl and some Perl libraries. You can use cpanm, cpan or any other way to install them.

  **cpanm:**
  ```bash
  curl -L http://cpanmin.us | perl - App::cpanminus
  cpanm install Net::TcpDumpLog NetPacket::IP NetPacket::UDP Getopt::Long
  ```

  **cpan:**
  ```bash
  cpan install Net::TcpDumpLog NetPacket::IP NetPacket::UDP Getopt::Long
  ```

## Docker Build

```bash
docker build -t bugre/pcap2mpegts:latest -t bugre/pcap2mpegts:$(awk -F 'version="|"' '/LABEL version="/{print $2}' < ./Dockerfile) .
docker push ...
```

### Apple Silicon for AMD64/Intel

```bash
docker buildx build --platform linux/amd64 -t bugre/pcap2mpegts:latest -t bugre/pcap2mpegts:$(awk -F 'version="|"' '/LABEL version="/{print $2}' < ./Dockerfile) .
docker push bugre/pcap2mpegts:latest && docker push bugre/pcap2mpegts:$(awk -F 'version="|"' '/LABEL version="/{print $2}' < ./Dockerfile)
```

## FAQ

**Q: Can I extract multiple streams from one PCAP?**  
A: Yes. Use `-i <mcast_ip> -p <port>` to filter by multicast group and UDP port so the output contains only one stream.

**Q: What format does the output have?**  
A: Standard MPEG Transport Stream (.ts) compatible with ffmpeg, VLC, dvb-inspector, and similar tools.

**Q: Do I need to join the multicast group before capturing?**  
A: Yes. The multicast group must already be joined on the same server/NIC so traffic flows to the interface you capture from.

## Credits

Based on a script posted by walto at [PerlMonks](https://www.perlmonks.org/?node_id=661366).
