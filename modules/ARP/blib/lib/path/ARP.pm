#
# Perl ARP Extension
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
package path::ARP;

use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use ARP ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.3';

require XSLoader;
XSLoader::load('path::ARP', $VERSION);

# Preloaded methods go here.

1;
__END__

=head1 NAME

ARP - Perl extension for creating ARP packets

=head1 SYNOPSIS

  use path::ARP;
  path::ARP::send_packet('lo',                 # Device
                         '127.0.0.1',          # Source IP
		         '127.0.0.1',          # Destination IP
		         'aa:bb:cc:aa:bb:cc',  # Source MAC
		         'aa:bb:cc:aa:bb:cc',  # Destinaton MAC
		         'reply');             # ARP operation

path::ARP::get_mac("eth0",$mac);
print "$mac\n";

path::ARP::arp_lookup($dev,"192.168.1.1",$mac);
print "192.168.1.1 has got mac $mac\n";

=head2 DESCRIPTION

This module can be used to create and send ARP packets and to
get the mac address of an ethernet interface or ip address.

=item B<send_packet()>

  path::ARP::send_packet('lo',                 # Device
                         '127.0.0.1',          # Source IP
		         '127.0.0.1',          # Destination IP
		         'aa:bb:cc:aa:bb:cc',  # Source MAC
		         'aa:bb:cc:aa:bb:cc',  # Destinaton MAC
		         'reply');             # ARP operation

  I think this is self documentating.
  ARP operation can be one of the following values:
  request, reply, revrequest, revreply, invrequest, invreply.
  The default ARP operation is reply.

=item B<get_mac()>

  path::ARP::get_mac("eth0",$mac);

  This gets the MAC address of the eth0 interface and stores 
  it in the variable $mac.

=item B<arp_lookup()>

  path::ARP::arp_lookup($dev,"192.168.1.1",$mac);

  This looks up the MAC address for the ip address 192.168.1.1
  and stores it in the variable $mac.

=head1 SEE ALSO

 man -a arp

=head1 AUTHOR

 Bastian Ballmann [ Crazydj@chaostal.de ]
 http://www.crazydj.de

=head1 COPYRIGHT AND LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.1 or,
at your option, any later version of Perl 5 you may have available.


=cut
