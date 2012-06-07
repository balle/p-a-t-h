package path::config;

# Central P.A.T.H Configuration Module
#
# For more information please read the POD documentation
#
# Programmed by Bastian Ballmann [ Crazydj@chaostal.de ]
# http://www.crazydj.de
#
# Last Update: 24.07.2004
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


###[ Loading modules ]###

use Net::Pcap;
use XML::Simple;
use Carp qw(croak);


###[ Klassenvariablen ]###

# Config Object and Hashes
my (%obj,$obj);


# Create a new config object
sub new
{
    my $class = shift;
    $obj{'target'} = [];
    $obj{'source'} = [];
    $obj{'connection'} = [];
    $obj{'port'} = [];
    $obj{'device'} = "";
    $obj{'hex'} = 0;
    $obj = bless \%obj, $class;
    return $obj;
}


# Check the configuration
sub check
{
    my $obj = shift;
    my %args = @_;
    my $code = 0;    

    # Device config
    if($args{'i'} eq "")
    {
	my $errbuf;
	$obj->{'device'} = Net::Pcap::lookupdev(\$errbuf);
    }
    else
    {
	$obj->{'device'} = $args{'i'};
    }

    # Target Config
    if($args{'h'})
    {
        # Target list
	if($args{'h'} =~ /\,/g)
	{
	    @{$obj->{'targetlist'}} = split(/\,/,$args{'h'});
	    for(@{$obj->{'targetlist'}}){ $code = 1 if(check_ip($_) == 1) }
	}

        # Target range
	elsif($args{'h'} =~ /\-/)
	{
	    my ($start,$stop) = split(/\-/,$args{'h'});
	    $code = 1 if(check_ip($start) == 1);
	    $code = 1 if(check_ip($stop) == 1);
	    $obj->{'targetlist'} = get_ips($start,$stop);
	}

        # Single Target
	else
	{
	    $code = 1 if(check_ip($args{'h'}) == 1);
	    push @{$obj->{'targetlist'}}, $args{'h'};
	}
    }

    # Source Config
    if($args{'s'})
    {
        # Source list
	if($args{'s'} =~ /\,/g)
	{
	    @{$obj->{'sourcelist'}} = split(/\,/,$args{'s'});
	    for(@{$obj->{'sourcelist'}}){ $code = 1 if(check_ip($_) == 1) }
	}

        # Source range
	elsif($args{'s'} =~ /\-/)
	{
	    my ($start,$stop) = split(/\-/,$args{'s'});
	    $code = 1 if(check_ip($start) == 1);
	    $code = 1 if(check_ip($stop) == 1);
	    $obj->{sourcelist} = get_ips($start,$stop);
	}
	else
	{
	    $code = 1 if(check_ip($args{'s'}) == 1);
	    push @{$obj->{'sourcelist'}}, $args{'s'};
	}
    }

    # Connection Config
    if($args{'c'})
    {
	@{$obj->{'connection'}} = split(/\-/,$args{'c'});
	for(@{$obj->{'connection'}}){ $code = 1 if(check_ip($_) == 1) }
	$code = 1 if(scalar(@{$obj->{connection}}) > 2);
    }

    # Port Config
    if($args{'p'})
    {
	# Port List?
	if($args{'p'} =~ /\,/)
	{
	    @{$obj->{'port'}} = split(/\,/,$args{'p'});
	}

	# Port Range?
	elsif($args{'p'} =~ /\-/)
	{
		my($start,$stop) = split(/\-/,$args{'p'});
		for(my $i=$start; $i <= $stop; $i++) { push @{$obj->{'port'}}, $i; }
	}

	# Single Port
	else
	{
	    push @{$obj{'port'}},$args{'p'};
	}
    }

    # Was there an error?
    ($code == 1) ? return $code : return $obj;
}


# Print configuration
sub print
{
    my $obj = shift;

    # Device 
    print "Device $obj->{'device'}\n";

    # Port Config
    print "Ports ";
    map { print } @{$obj->{'port'}};
    print "\n";

    # Target Config
    print "Targets ";
    map { print } @{$obj->{'targetlist'}};
    print "\n";

    # Source Config
    print "Sources ";
    map { print } @{$obj->{'sourcelist'}};
    print "\n";

    # Connection
    print "Connection $obj->{'connection'}->[0] <--> $obj->{'connection'}->[1]\n\n";
}


# Change target
sub set_target
{
    my ($obj,@host) = @_;
    my $code;
    for(@host){ $code = 1 if(check_ip($_) == 1) }    
    @{$obj->{'targetlist'}} = @host;
    ($code == 1) ? return $code : return $obj;
}


# Change source
sub set_source
{
    my ($obj,@host) = @_;
    my $code = 0;
    for(@host){ $code = 1 if(check_ip($_) == 1) }    
    @{$obj->{'sourcelist'}} = @host;
    ($code == 1) ? return $code : return $obj;
}


# Change connection
sub set_connection
{
    my ($obj,$connection) = @_;
    my $code = 0;
    @{$obj->{'connection'}} = split(/\-/,$connection);
    for(@{$obj->{'connection'}}){ $code = 1 if(check_ip($_) == 1) }
    $code = 1 if(scalar(@{$obj->{connection}}) > 2);
    ($code == 1) ? return $code : return $obj;
}


# Change port
sub set_port
{
    my ($obj,@port) = @_;
    @{$obj->{'port'}} = @port;
    return $obj;
}


# Change device
sub set_device { return $_[0]->{'device'} = $_[1]; }


# Set flags
sub set_flags
{
    my ($obj, %flags) = @_;
    $obj->{'syn'} = $flags{'syn'};
    $obj->{'ack'} = $flags{'ack'};
    $obj->{'rst'} = $flags{'rst'};
    $obj->{'fin'} = $flags{'fin'};
    $obj->{'psh'} = $flags{'psh'};
    $obj->{'urg'} = $flags{'urg'};
    return $obj;
}

# Set TCP options
sub set_tcpopt
{
    my ($obj,%opts) = @_;
    $obj->set_flags(%opts);
    $obj->{'win'} = $opts{'win'};
    $obj->{data} = $opts{data};
    $obj->{seq} = $opts{seq};
    $obj->{'ack_seq'} = $opts{'ack_seq'};
    $obj->{'src_port'} = $opts{'src_port'};
    $obj->{'dst_port'} = $opts{'dst_port'};
    $obj->{protocol} = "tcp";
    return $obj;
}

# Set UDP options
sub set_udpopt
{
    my ($obj,%opts) = @_;
    $obj->{'src_port'} = $opts{'src_port'};
    $obj->{'dst_port'} = $opts{'dst_port'};
    $obj->{data} = $opts{data};
    $obj->{protocol} = "udp";
    return $obj;
}

# Set ICMP options
sub set_icmpopt
{
    my ($obj,%opts) = @_;B
    $obj->{type} = $opts{type};
    $obj->{code} = $opts{code};
    $obj->{gateway} = $opts{gateway};
    $obj->{mtu} = $opts{mtu};
    $obj->{data} = $opts{data};
    $obj->{protocol} = "icmp";
    return $obj;    
}

# Set IP options
sub set_ipopt
{
    my ($obj,%opts) = @_;
    $obj->{ttl} = $opts{ttl};
    $obj->{tos} = $opts{tos};
    $obj->{frag} = $opts{frag};
    $obj->{sourcelist}->[0] = $opts{spoof};
    $obj->{targetlist}->[0] = $opts{target};
    return $obj;    
}

# Set general packet options
sub set_opt
{
    my ($obj,%opts) = @_;
    $obj->set_ipopt(%opts);
    $obj->{protocol} = $opts{protocol};
    $obj->{device} = $opts{device};

    if($opts{protocol} eq "tcp")
    {
	$obj->set_tcpopt(%opts);
    }
    elsif($opts{protocol} eq "udp")
    {
	$obj->set_udpopt(%opts);
    }
    elsif($opts{protocol} eq "icmp")
    {
	$obj->set_icmpopt(%opts);
    }

    return $obj;
}

# Extract target host(s)
sub get_target { return @{$_[0]->{'targetlist'}}; }

# Extract source host(s)
sub get_source { return @{$_[0]->{'sourcelist'}}; }

# Extract connection(s)
sub get_connection { return $_[0]->{'connection'}; }

# Extract port(s)
sub get_port { return @{$_[0]->{'port'}}; }

# Extract device
sub get_device { return $_[0]->{'device'}; }

# Get IP options
sub get_ipopt
{
    my $obj = shift;
    my %opts;
    $opts{'spoof'} = $obj->{sourcelist}->[0];
    $opts{'target'} = $obj->{targetlist}->[0];
    $opts{'frag'} = $obj->{frag};
    $opts{'ttl'} = $obj->{ttl};
    $opts{tos} = $obj->{tos};
    return %opts;
}

# Get TCP options
sub get_tcpopt
{
    my $obj = shift;
    my %opts = shift;
    $opts{'src_port'} = $obj->{'src_port'};
    $opts{'dst_port'} = $obj->{'dst_port'};
    $opts{'syn'} = $obj->{syn};
    $opts{'ack'} = $obj->{ack};
    $opts{'rst'} = $obj->{rst};
    $opts{'fin'} = $obj->{fin};
    $opts{'psh'} = $obj->{psh};
    $opts{'urg'} = $obj->{urg};
    $opts{'seq'} = $obj->{seq};
    $opts{'ack_seq'} = $obj->{'ack_seq'};
    $opts{win} = $obj->{win};
    $opts{data} = $obj->{data};
}

# Get UDP options
sub get_udpopt
{
    my $obj = shift;
    my %opts = shift;
    $opts{'src_port'} = $obj->{'src_port'};
    $opts{'dst_port'} = $obj->{'dst_port'}; 
    $opts{data} = $obj->{data};
}

# Get ICMP options
sub get_icmpopt
{
    my $obj = shift;
    my %opts = shift;
    $opts{type} = $obj->{type};
    $opts{code} = $obj->{code};
    $opts{gateway} = $obj->{gateway};
    $opts{data} = $obj->{data};
    $opts{mtu} = $obj->{mtu};
}

# Get general packet options
sub get_opt
{
    my $obj = shift;
    my %opts = $obj->get_ipopt();

    if($obj->{protocol} eq "tcp")
    {
	$obj->get_tcpopt(%opts);
    }
    elsif($obj->{protocol} eq "udp")
    {
	$obj->get_udpopt(%opts);
    }
    elsif($obj->{protocol} eq "icmp")
    {
	$obj->get_icmpopt(%opts);
    }

    return %opts;
}

# check or extract the used protocol
sub get_protocol
{
    my $obj = shift;
    my $proto = shift;

    if($proto ne "")
    {
	if($obj->{protocol} eq $proto)
	{
	    return 1;
	}
	else
	{
	    return 0;
	}
    }
    else
    {
	return $obj->{protocol};
    }
}

# extract the flags
sub get_flags
{
    my $obj = shift;
    my %opts;
    $opts{'syn'} = $obj->{syn};
    $opts{'ack'} = $obj->{ack};
    $opts{'rst'} = $obj->{rst};
    $opts{'fin'} = $obj->{fin};
    $opts{'psh'} = $obj->{psh};
    $opts{'urg'} = $obj->{urg};
    return %opts;
}

# Is the connection value defined?
sub connection { ($_[0]->{'connection'}->[0] ne "") ? return 1 : return 0; }

# Is the target value defined?
sub target { ($_[0]->{'targetlist'}->[0] ne "") ? return 1 : return 0; }

# Is the source value defined?
sub source { ($_[0]->{'sourcelist'}->[0] ne "") ? return 1 : return 0; }

# Is the port value defined?
sub port { ($_[0]->{'port'}->[0] ne "") ? return 1 : return 0; }


# Check MAC address
sub check_mac { ($_[0] !~ /^[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}$/) ? return 1 : return 0; }


# Check if ip address is correct
sub check_ip
{
    my $ip = shift;
    my @ip = split(/\./,$ip);
    my $code = 0;

    # More than 4 Bytes long?
    $code = 1 if(scalar(@ip != 4));

    # Is a value bigger than 256?
    # Are there any disallowed characters?
    for(@ip)
    {
	if($_ !~ /(\d)+/)
	{
	    $code = 1;
	}
	elsif($_ > 256)
	{
	    $code = 1;
	}
    }
    
    return $code;
}


# Get ips
sub get_ips
{
    my $start = shift;
    my $stop = shift;
    my @ips;

    my @start = split(/\./,$start); 
    my @stop = split(/\./,$stop); 

    my $start_dec = (($start[0]*16777216)+($start[1]*65536)+($start[2]*256)+$start[3]);
    my $stop_dec = (($stop[0]*16777216)+($stop[1]*65536)+($stop[2]*256)+$stop[3]);

    while($start_dec < $stop_dec + 1)
    {
	my @bytes;
	my $rem;
	
	$bytes[0] = int $start_dec/16777216;
	$rem = $start_dec % 16777216;
	$bytes[1] = int $rem/65536;
	$rem = $rem % 65536;
	$bytes[2] = int $rem/256;
	$rem = $rem % 256;
	$bytes[3] = $rem;
	my $ipaddr = join '.', @bytes;
	push @ips, $ipaddr;
	$start_dec++;
    }
    
    return \@ips;
}


# Create a pcap expression from configuration
sub pcap
{
    my $obj = shift;
    my $pcap = "";

    if($obj->get_target)
    {	
	map { $pcap .= "host $_ or " } @{$obj{'targetlist'}};
	chop $pcap; chop $pcap; chop $pcap;
    }
    elsif($obj->{'connection'}->[0])
    {
	$pcap .= "host $obj->{'connection'}->[0] or host $obj->{'connection'}->[1] ";
    }

    $pcap .= "and " if($pcap ne "");

    map { $pcap .= "port $_ or " } @{$obj{'port'}};
    chop $pcap; chop $pcap; chop $pcap;
    $pcap .= "and " if($pcap ne "");
    return $pcap;
}


###[ Parse a XML config file ]###

# Read a xml config file
sub readcfg { return XMLin($_[0]) or die "Cannot parse file $_[0]!\n$!\n"; }


# Write a xml config file
sub writecfg 
{ 
    my ($cfg,$file) = @_;

    open(OUT,">$file") or die "Cannot write file $file\n$!\n";
    print OUT "<?xml version=\"1.0\"?>\n";
    print OUT "<!DOCTYPE config SYSTEM \"../dtd/config.dtd\">\n";
    print OUT "<config>\n";
    
    print OUT "<parameter>\n";
    while(my ($key,$value) = each %{$cfg->{'parameter'}})
    {
	if($key eq "brute")
	{
	    print OUT "<brute>\n";
	    while(my ($key,$value) = each %{$cfg->{'parameter'}->{'brute'}})
	    {
		print OUT "<$key>$value</$key>\n";
	    }
	    print OUT "</brute>\n";
	}
	elsif($key eq "crazysniffer")
	{
	    print OUT "<crazysniffer>\n";
	    while(my ($key,$value) = each %{$cfg->{'parameter'}->{'crazysniffer'}})
	    {
		if($key eq "print")
		{
		    print OUT "<print>\n";
		    while(my ($key,$value) = each %{$cfg->{'parameter'}->{'crazysniffer'}->{'print'}})
		    {
			print OUT "<$key>$value</$key>\n";
		    }
		    print OUT "</print>\n";
		}
		elsif($key eq "mode")
		{
		    print OUT "<mode>\n";
		    while(my ($key,$value) = each %{$cfg->{'parameter'}->{'crazysniffer'}->{'mode'}})
		    {
			print OUT "<$key>$value</$key>\n";
		    }
		    print OUT "</mode>\n";
		}
	    }
	    print OUT "</crazysniffer>\n";
	}
	elsif($key eq "feedsnort")
	{
	    print OUT "<feedsnort>\n";
	    while(my ($key,$value) = each %{$cfg->{'parameter'}->{'feedsnort'}})
	    {
		if($key eq "ports")
		{
		    print OUT "<ports>\n";
		    while(my ($key,$value) = each %{$cfg->{'parameter'}->{'feedsnort'}->{'ports'}})
		    {
			print OUT "<$key>$value</$key>\n";
		    }
		    print OUT "</ports>\n";
		}
		else
		{
		    print OUT "<$key>$value</$key>\n";
		}
	    }
	    print OUT "</feedsnort>\n";	    
	}
	elsif($key eq "hijackd")
	{
	    print OUT "<hijackd>\n";
	    while(my ($key,$value) = each %{$cfg->{'parameter'}->{'hijackd'}})
	    {
		print OUT "<$key>$value</$key>\n";
	    }
	    print OUT "</hijackd>\n";
	}
	elsif($key eq "icmpredir")
	{
	    print OUT "<icmpredir>\n";
	    while(my ($key,$value) = each %{$cfg->{'parameter'}->{'icmpredir'}})
	    {
		print OUT "<$key>$value</$key>\n";
	    }
	    print OUT "</icmpredir>\n";
	}
	else
	{
	    print OUT "<$key>$value</$key>\n";
	}
    }
    print OUT "</parameter>\n";

    print OUT "<packet>\n";
    while(my ($key,$value) = each %{$cfg->{'packet'}})
    {
	if($key eq "ip")
	{
	    print OUT "<ip>\n";
	    while(my ($key,$value) = each %{$cfg->{'packet'}->{'ip'}})
	    {
		print OUT "<$key>$value</$key>\n";
	    }
	    print OUT "</ip>\n";
	}
	elsif($key eq "tcp")
	{
	    print OUT "<tcp>\n";
	    while(my ($key,$value) = each %{$cfg->{'packet'}->{'tcp'}})
	    {
		if($key eq "flags")
		{
		    print OUT "<flags>\n";
		    while(my ($key,$value) = each %{$cfg->{'packet'}->{'tcp'}->{'flags'}})
		    {
			print OUT "<$key>$value</$key>\n";
		    }
		    print OUT "</flags>\n";
		}
		else
		{
		    print OUT "<$key>$value</$key>\n";
		}
	    }
	    print OUT "</tcp>\n";
	}
	elsif($key eq "udp")
	{
	    print OUT "<udp>\n";
	    while(my ($key,$value) = each %{$cfg->{'packet'}->{'udp'}})
	    {
		print OUT "<$key>$value</$key>\n";
	    }
	    print OUT "</udp>\n";
	}
	elsif($key eq "icmp")
	{
	    print OUT "<icmp>\n";
	    while(my ($key,$value) = each %{$cfg->{'packet'}->{'icmp'}})
	    {
		print OUT "<$key>$value</$key>\n";
	    }
	    print OUT "</icmp>\n";
	}
	elsif($key eq "arp")
	{
	    print OUT "<arp>\n";
	    while(my ($key,$value) = each %{$cfg->{'packet'}->{'arp'}})
	    {
		print OUT "<$key>$value</$key>\n";
	    }
	    print OUT "</arp>\n";
	}
	else
	{
	    print OUT "<$key>$value</$key>\n";
	}
    }
    print OUT "</packet>\n";

    print OUT "</config>\n";
    close(OUT);
}


# Generate a config object
# out of a config file
sub register_config
{
    my ($obj,%args) = @_;
    $obj->set_device($args->{'parameter'}->{'device'});
    $obj->set_source($args->{'packet'}->{'ip'}->{'srcip'});
    $obj->set_target($args->{'packet'}->{'ip'}->{'dstip'});
    $obj->set_port($args->{'parameter'}->{'ports'});
    return $obj;
}

1;


###[ Thats the end folks ]###


__END__


###[ POD Documentation ]###

=pod
=head2 NAME

    Config.pm  --  P.A.T.H Configuration

=head2 SYNOPSIS

    use path::config;
    use Getopt::Std;

    getopts('h:c:p:i:',%args);
    $cfg = path::config->new();
    if($cfg->check(%args) == 1)
    {
	exit(1);
    }
    
    if($cfg->connection)
    {
	@connect = $cfg->connection;
	print "Connection $connection[0] <--> $connection[1]\n";
    }

	print "Ports: ";
        map { print } $cfg->get_port;
 	print "\n";
   }


=head2 DESCRIPTION

   This module checks the configuration for P.A.T.H. scripts.
   It parses the parameter like host (lists,ranges), connections,
   port (lists,ranges) and device.
   You can set and get config parameters.
   This module can also read and parse a configuration file.


=head2 METHODS

   new
   check
   print
   get_device
   get_target
   get_source
   get_connection
   get_port
   get_flags
   get_ipopt
   get_tcpopt
   get_udpopt
   get_icmpopt
   get_opt
   set_flags
   set_ipopt
   set_tcpopt
   set_udpopt
   set_cmpopt
   set_opt
   set_device
   set_target
   set_source
   set_connection
   set_port
   target
   source
   port
   connection
   pcap
   readcfg
   register_config
   check_ip
   check_mac


=head2 Description of methods

=item B<new()>

   $cfg = config->new()

   This creates a new config object.

=item B<check()>

   $cfg->check(%args);

   This method parses and checks the parameter in the hash %args.
   It return a value of 1 if there was an error.
   %args can contain the following things:
   i: device
   c: connection (target1-target2)
   h: host (list: host1,host2 // range host1-host3)
   p: port (list or range)


=item B<print()>

   $cfg->print();

   This will print the configuration to STDOUT.


=item B<get_device()>

   $cfg->get_device

   This method returns the configured device.
   All the other get_* methods do the same.
   NOTE: get_target, get_source and get_port
   always return a list!

=item B<set_device()>

   $cfg->set_device("eth1");

   This method changes the device configuration and
   returns the new object.
   All teh other set_* methods are used similar and
   do the same.


=item B<set_opt>

    $cfg->set_opt(%config);

    This method sets the packet options like TCP flags, 
    window size and so on. There is also a set_* method
    for each supported protocol.
    See the section configuration hash for a description
    of the hash %config.

=item B<get_opt>
    
    %config = $cfg->get_opt();

    This method can be used to receive all the packet
    option from the config object. There is also a get_*
    method for each supported protcol.
    See the section configuration hash for a description
    of the hash %config.

=item B<connection()>

   $cfg->connection;

   This method return the boolean value true if a connection
   is found in the configuration.
   The port and host method are used the same way.

=item B<pcap()>

   $string = $cfg->pcap();

   Create a pcap expression from the configuration like:
   host 192.168.1.1 and port 23 or port 21

=item B<readcfg()>

   %config = config::readcfg($file);

   This function will parse a xml config file.

=item B<register_config()>

    $cfg->register_config(%config);

    This method stores the default values like target
    and device into the config object.

=item B<check_ip()>

    $cfg->check_ip('192.168.3.33');

    This method checks if an IP address is valid.
    It returns 1 on failure and 0 on success.

=item B<check_mac()>

    $cfg->check_mac('aa:bb:cc:aa:bb:cc');

    This method checks if an MAC address is valid.
    It returns 1 on failure and 0 on success.

=item B<The configuration hash>

    The configuration hash has the following values
    (depeding on which protocol should be configured):
    $opts{'protocol'}
    $opts{'spoof'}
    $opts{'target'}
    $opts{'frag'}
    $opts{'ttl'}
    $opts{tos}
    $opts{'src_port'}
    $opts{'dst_port'}
    $opts{'syn'}
    $opts{'ack'}
    $opts{'rst'}
    $opts{'fin'}
    $opts{'psh'}
    $opts{'urg'}
    $opts{'seq'}
    $opts{'ack_seq'}
    $opts{'win'}
    $opts{'data'}
    $opts{'type'}
    $opts{'code'}
    $opts{'gateway'}
    $opts{'mtu'}
    $opts{'smac'}
    $opts{'dmac'}
    $opts{'arpop'}

=head2 BUGS

  Currently there are no known bugs...
  Please send bug reports to Crazydj@chaostal.de


=head2 AUTHOR

   Bastian Ballmann [ Crazydj@chaostal.de ]
   http://p-a-t-h.sourceforge.net


=head2 COPYRIGHT

   This module is free software.
   It is licensed under GPL.

