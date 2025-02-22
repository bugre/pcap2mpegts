#!/usr/bin/env perl -w
#
# It's based/inspired by script posted by walto at 
#  ==> https://www.perlmonks.org/?node_id=661366
#
# Copyright Werner <wxxx333@gmail.com>
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
# To use, yoyu'll need some modules.. install with:
#  cpan install Net::TcpDumpLog NetPacket::IP NetPacket::UDP Getopt::Long
#
# 20200217 - bugre: Initial copy/adjustment.
# 20200303 - bugre: Check output file existence and ask/overwrite output file
# 20200311 - bugre: Add multicast group destination UDP Port
#                   to differentiate multiple streams on the same IP/capture
# 20200422 - bugre: Add multicast group IP filtering ( also requeries dest_port)
# 20200424 - bugre: Add some messages and progress notification
# 20250222 - bugre: Create container (docker) image and minor changes
# 20250222 - bugre: Fix: first try to load the input and then open the output, 
#                   to avoid creating empty output if error on loading input
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


$SIG{INT} = sub { die "Caught a sigint $!" };
$SIG{TERM} = sub { die "Caught a sigterm $!" };

GetOptions( 'l|logfile=s' => \$logfile, 'o|outfile=s' => \$outfile, 
            'y|yes' => \$foverwrite,
            'p|dest_port=i' => \$dest_port, 'i|dest_ip=s' => \$dest_ip);

die "Usage: $0 [-y (Overwrite)] [-p dest_port] [-i dest_ip -p dest_port] -l LOGFILE(PCAP) -o OUTFILE\n\n"
  unless ( $logfile ne '' && $outfile ne '');

die "Usage: $0 [-y (Overwrite)] [-p dest_port] [-i dest_ip -p dest_port] -l LOGFILE(PCAP) -o OUTFILE\n\t" . 
    "when multicast group IP is specified you must also specify udp port.\n\n"
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

# first try to open the input, if error, we avoid creating the output...
$| = 1;
print ("Loading PCAP file: $logfile ...\n");
my $log = Net::TcpDumpLog->new();
$log->read("$logfile") || die "Can't read $logfile $!\n";


open OUT, ">$outfile" or die "Can't open $outfile $!\n";


print ("Start processing ...: ");
my @Indexes = $log->indexes;

foreach my $index (@Indexes) {
  showProgress ();
  # my ( $length_orig, $length_incl, $drops, $secs, $msecs ) = $log->header($index);
  my $data = $log->data($index);
  my ( $ether_dest, $ether_src, $ether_type, $ether_data ) = unpack('H12H12H4a*', $data );
  
  if ( $ether_data eq '' ) {
    print STDERR "log=>", $ether_dest; 
    next;
  }
  my $ip_obj = NetPacket::IP->decode($ether_data);
  next if ( $dest_ip ne '' && ( $dest_ip ne $ip_obj->{dest_ip} ));   # if filtering by IP, only process data on that IP
  
  my $udp_obj = NetPacket::UDP->decode( $ip_obj->{data} );
  next if ( $dest_port && ( $dest_port != $udp_obj->{dest_port} ) ); # if filtering by dest_port, save only that dest_port

  my @bytes_ip = split /\./, ( $ip_obj->{dest_ip} );
  if ( $bytes_ip[0] >= 224 and $bytes_ip[0] <= 240 ){                # only extract data from multicast addresses
    print OUT $udp_obj->{data};;
  }
}
print "\n";
