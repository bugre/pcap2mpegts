# pcap2mpegts
pcap2mpegts allows you to extract MPEG video from "pcap" capture (tcpdump/wireshark) of UDP Multicast traffic. So in short, 
it allow you to convert a pcap capture file to a valid mpeg ts video file.

I had the need troubleshoot multicast traffic, and the closest way to the network card to capture the traffic to evaluate packet loss or damage is using tools like tcpdump, wireshark or other pcap capture option.

But the evaluation of the data stream on a MPEG (video/audio) level using tools like dvbinspector, ffmpeg and others, needs the data correctly formatted as a MPEG TransportStream.

If the pcap file captured has multiple transport stream, on different IP (group) or UDP Ports, you must use the `-p <dst_port>` and or `-i <mcast IP> -p <dst_port>` so the extracted TS has only the selected mpeg audio/video.

*credits:*
> It's based/inspired by script posted by walto at 
>  ==> https://www.perlmonks.org/?node_id=661366


### install
 * clone this repo or copy the pcap2mpegts.pl file to your system.
 * you'll need perl and some perl libraries. You can use cpan or any other way to install them.
	 * cpan install Net::TcpDumpLog
	 * cpan install NetPacket::IP
	 * cpan install NetPacket::UDP
	 * cpan install Getopt::Long
 

### usage
*minimal*
```
$ pcap2mpegts.pl -l <pcal_capture_file.pcap> -o <output_mpeg.ts>
```

*other options*
```
$ pcap2mpegts.pl -y -i 239.100.0.1 -p 2000 -l multi_ts_capture.pcap -o single-stream-output.ts
 -y                          # ATENTION **overwrite** the output file without confirmation.
 -p dest_port                # filter mcast traffic extraction by UDP Destination Port
 -i dest_ip                  # filter mcast traffic extraction by mcast group IP. *MUST* also specify port if IP is specified

```

## how to capture data

Some capture options

Ensure that your multicast group `239.100.0.1` (multicast group in this example) is being consumed (joined), so that the traffic is flowing on the *NIC* (eth0 in this example) that you'll capture
    
    tcpdump -nn -s0 -B 8192 -i eth0 host 239.100.0.1 
    
or
    
    tcpdump -nn -s0 -B 8192 -i eth0 host 239.100.0.1 and udp
    

