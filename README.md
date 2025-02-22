# pcap2mpegts
pcap2mpegts allows you to extract MPEG video from "pcap" capture (tcpdump/wireshark) of UDP Multicast traffic. So in short, 
it allow you to convert a pcap capture file to a valid mpeg ts video file.

I had the need troubleshoot multicast traffic, and the closest way to the network card to capture the traffic to evaluate packet loss or damage is using tools like tcpdump, wireshark or other pcap capture option.

But the evaluation of the data stream on a MPEG (video/audio) level using tools like dvbinspector, ffmpeg and others, needs the data correctly formatted as a MPEG TransportStream.

If the pcap file captured has multiple transport stream, on different IP (group) or UDP Ports, you must use the `-p <dst_port>` and or `-i <mcast IP> -p <dst_port>` so that the extracted TS has only the selected mpeg audio/video.

### credits:
> It's based on script posted by walto at 
>  ==> https://www.perlmonks.org/?node_id=661366



### How to use:
#### Command line options
```
 -l|--logfile <file>        # input capture (PCAP) log file
 -o|--outfile <file>        # output transport stream file
 -y|--yes                   # **overwrite** the output file without confirmation.
 -p|--dest_port dest_port   # filter extraction by UDP Destination Port
 -i|--dest_ip dest_ip       # filter extraction by mcast group IP. 
                              *MUST* also specify port if IP is specified

```

#### docker/container (no need to install perl or depencies)

```
docker run --rm -v $PWD:/inout bugre/pcap2mpegts \
      --yes                                      \
      --logfile /inout/mycapture.pcap            \
      --outfile /inout/mycapture.ts
```

------------------------
#### perl source version

```
$ pcap2mpegts.pl -l <pcal_capture_file.pcap> -o <output_mpeg.ts>
```

* with filtering
```
$ pcap2mpegts.pl -y -i 239.100.0.1 -p 2000 -l multi_ts_capture.pcap -o single-stream-output.ts
```

##### install
 * clone this repo or copy the pcap2mpegts.pl file to your system.
 * you'll need perl and some perl libraries. You can use cpanm, cpan or any other way to install them.
	* cpanm:
		* curl -L http://cpanmin.us | perl - App::cpanminus
		* cpanm install Net::TcpDumpLog NetPacket::IP NetPacket::UDP Getopt::Long
	* cpan
	 	* cpan install Net::TcpDumpLog NetPacket::IP NetPacket::UDP Getopt::Long
 
 


## How to capture data

You *must ansure* that your multicast group `239.100.0.1/port` (in this example) is already joined on the same server/NIC, so that the traffic is flowing on the *NIC* that you'll capture.

```
	## specific multicast group (IP) and destination port on NIC eth0
	tcpdump -nn -s0 -B 8192 -w mycapture.pcap -i eth0 host 239.100.0.1 and port 3456 and udp

	## specific multicast group (IP) on NIC eth0
	tcpdump -nn -s0 -B 8192 -w mycapture.pcap -i eth0 host 239.100.0.1 and udp

	## all udp traffic seen on the NIC
	tcpdump -nn -s0 -B 8192 -w mycapture.pcap -i eth0 udp
```

### Docker build example...
```
docker build -t bugre/pcap2mpegts:latest -t bugre/pcap2mpegts:$(awk -F 'version="|"' '/LABEL version="/{print $2}' < ./Dockerfile) .
docker push ...
```

#### ... on Apple Silicon for AMD64/intel
```
docker buildx build --platform linux/amd64 -t bugre/pcap2mpegts:latest -t bugre/pcap2mpegts:$(awk -F 'version="|"' '/LABEL version="/{print $2}' < ./Dockerfile) .

docker push bugre/pcap2mpegts:latest && docker push bugre/pcap2mpegts:$(awk -F 'version="|"' '/LABEL version="/{print $2}' < ./Dockerfile)
```