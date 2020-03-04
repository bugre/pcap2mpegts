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
#

use strict;
use Net::TcpDumpLog;
use NetPacket::IP;
use NetPacket::UDP qw(:strip);
use Getopt::Long;

my $outfile = '';
my $logfile = '';
my $foverwrite = 0;  # overwrite output file. Default to false



GetOptions( 'l|logfile=s' => \$logfile, 'o|outfile=s' => \$outfile, 
            'y|yes' => \$foverwrite);

die "Usage: pcap2mpeg.pl [-y (Overwrite)] -l LOGFILE -o OUTFILE"
  unless ( defined $logfile && defined $outfile );

if ( -e $outfile && ! $foverwrite ) {
  print ("File \"$outfile\" already exists. Overwrite? (y/n):");
  my $over = <STDIN>; chomp ($over);
  if ( $over ne "y" ) {
    die "Exiting... remove output file first!\n\n"
  } 
  $foverwrite = 1;
}

open OUT, ">$outfile" or die "Can not open $outfile $!\n";

my $log = Net::TcpDumpLog->new();
$log->read("$logfile");
my @Indexes = $log->indexes;

foreach my $index (@Indexes) {
    my ( $length_orig, $length_incl, $drops, $secs, $msecs ) = $log->header($index);
    my $data = $log->data($index);
    my ( $ether_dest, $ether_src, $ether_type, $ether_data ) = unpack( 'H12H12H4a*', $data );
    my $ip_obj   = NetPacket::IP->decode($ether_data);
    my @bytes_ip = split /\./, ( $ip_obj->{dest_ip} );
    my $udp_obj  = NetPacket::UDP->decode( $ip_obj->{data} );
    if ( $bytes_ip[0] >= 224 and $bytes_ip[0] <= 240 ){    # only extract data from multicast addresses
        my $data_neu = $udp_obj->{data};
        print OUT $data_neu;
    }
}
