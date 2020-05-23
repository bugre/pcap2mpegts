#!/usr/bin/env perl -w
#
# It's based/inspired by script posted by walto at 
#  ==> https://www.perlmonks.org/?node_id=661366
#
# Copyright 2020 Werner <wxxx333@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it under the terms of 
# the GNU General Public License as published by the Free Software Foundation; 
# either version 2 of the License, or (at your option) any later version.
#
# Converts tcpdump or wireshark multicast/UDP capture from pcap format into mpeg video file.
#
# If the capture has multiple streams on differente IPs or different ports you must 
# specify the Multicast group Destination IP or Port.
#
# 20200217 - bugre: Initial copy/adjustment.
# 20200303 - bugre: Check output file existence and ask/overwrite output file
# 20200311 - bugre: Add multicast group destination UDP Port
#                   to differentiate multiple streams on the same IP/capture
# 20200422 - bugre: Add multicast group IP filtering ( also requeries dest_port)
# 20200424 - bugre: Add some messages and progress notification
#

use strict;
use Net::TcpDumpLog;
use NetPacket::IP;
use NetPacket::UDP qw(:strip);
use Getopt::Long;

my $outfile = '';
my $logfile = '';
my $foverwrite = 0;  # overwrite output file. Default to false
my $dest_port  = 0;  # mcast group PORT num to differentiate beween multiple streams on same IP
my $dest_ip    = ''; # mcast group IP to differentiate beween multiple streams on the same capture



GetOptions( 'l|logfile=s' => \$logfile, 'o|outfile=s' => \$outfile, 
            'y|yes' => \$foverwrite,
            'p|dest_port=i' => \$dest_port, 'i|dest_ip=s' => \$dest_ip);

die "Usage: $0 [-y (Overwrite)] [-p dest_port] [-i dest_ip -p dest_port] -l LOGFILE -o OUTFILE\n\n"
  unless ( $logfile ne '' && $outfile ne '');

die "Usage: pcap2mpegts.pl  [-y (Overwrite)] [-p dest_port] [-i dest_ip -p dest_port] -l LOGFILE -o OUTFILE\n\t" . 
    "when mcast group IP is specified you must also specify udp port number.\n\n"
  if ( $dest_ip ne '' && $dest_port == 0);

#==================
my $progressPos=0;  # remember progress state
my $progressFwd=1;
sub showProgress {
    local $| = 1;
    # print "\b", qw( | / - \ )[$progressPos++%4];
    if ( $progressFwd ){
      print ".";
      if ( $progressPos++ > 50 ) {
        $progressFwd = 0;
      }
    } else {
      print "\b \b";
      if ( $progressPos-- < 1 ) {
        $progressFwd = 1;
      }
    }
}
#==================

if ( -e $outfile && ! $foverwrite ) {
  print ("File \"$outfile\" already exists. Overwrite? (y/n):");
  my $over = <STDIN>; chomp ($over);
  if ( $over ne "y" ) {
    die "Exiting... remove output file first!\n\n"
  } 
  $foverwrite = 1;
}

open OUT, ">$outfile" or die "Can not open $outfile $!\n";

$| = 1;
print ("Loading PCAP file: $logfile ...\n");

my $log = Net::TcpDumpLog->new();
$log->read("$logfile");
my @Indexes = $log->indexes;

print ("Start processing ...: ");
foreach my $index (@Indexes) {
    showProgress ();
    my ( $length_orig, $length_incl, $drops, $secs, $msecs ) = $log->header($index);
    my $data = $log->data($index);
    my ( $ether_dest, $ether_src, $ether_type, $ether_data ) = unpack('H12H12H4a*', $data );
    my $ip_obj   = NetPacket::IP->decode($ether_data);

    next if ( $dest_ip ne '' && ( $dest_ip ne $ip_obj->{dest_ip} ));  ## if checking IP, only process data on that IP

    my @bytes_ip = split /\./, ( $ip_obj->{dest_ip} );
    my $udp_obj  = NetPacket::UDP->decode( $ip_obj->{data} );
    if ( $bytes_ip[0] >= 224 and $bytes_ip[0] <= 240 ){     # only extract data from multicast addresses
      my $data_neu = $udp_obj->{data};
      if ( $dest_port ) {                                   # if dest_port is defined, then only save if it's the desired dest_port
        if ( $dest_port == $udp_obj->{dest_port} ) {
          print OUT $data_neu;
        }
      } else {
        print OUT $data_neu;
      }
    }
}
print "\n";
