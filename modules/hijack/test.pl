#!/usr/bin/perl
#
# Perl hijack module test file
#
# Programmed by Bastian Ballmann
# Last update: 05.01.2004
#
# This program is free software; you can redistribute 
# it and/or modify it under the terms of the 
# GNU General Public License version 2 as published 
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will 
# be useful, but WITHOUT ANY WARRANTY; without even 
# the implied warranty of MERCHANTABILITY or FITNESS 
# FOR A PARTICULAR PURPOSE. 
# See the GNU General Public License for more details. 

use ExtUtils::testlib;
use path::hijack;
use Net::Pcap;

my ($errbuf, %header);
my $dev = Net::Pcap::lookupdev(\$errbuf);
my $pcap_dev = Net::Pcap::open_live($dev, 1024, 1, 1500, \$errbuf);
my $packet = Net::Pcap::next($pcap_dev, \%header);
my $connection = path::hijack->new($packet);
