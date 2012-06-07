#!/usr/bin/perl

eval 'exec /usr/bin/perl  -S $0 ${1+"$@"}'
    if 0; # not running under some shell
# IP-Packet - A packet generator written in Perl
#
# Programmed by Bastian Ballmann [ Crazydj@chaostal.de ]
# http://www.crazydj.de 
# 
# Last update: 24.07.2004
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

use Net::Pcap;     # Sniffin around
use Net::ARP;      # ARP stuff 
use path::config;  # P.A.T.H. configuration
use path::hijack;  # P.A.T.H. hijacking stuff
use Getopt::Long;  # Parsing parameter
use strict;        # Be strict!

# Do you have X and Tk?
BEGIN 
{
    eval{ require Tk; };              
    import Tk unless $@;

    eval{ require Tk::FileSelect; };  
    import Tk::FileSelect unless $@;

    eval{ require Tk::ProgressBar; }; 
    import Tk::ProgressBar unless $@;

    eval{ require Tk::Optionmenu; };  
    import Tk::Optionmenu unless $@;
};


###[ Global variables ]###

# Parameter hash
my $config = {};

# Config object
my $cfg = path::config->new();

# Bruteforce modes
my ($brute_sport, $brute_dport, $brute_icmp);

# Global Tk objects
my ($askproto, $top, $result, $spoof, $target, $frag, $ttl, $smac, $dmac, $icmptype, $icmpcode, $gateway, $mtu, $sport, $dport, $seqnum, $acknum, $win, $syn, $syn_flag, $ack, $ack_flag, $fin, $fin_flag, $rst, $rst_flag, $psh, $psh_flag, $urg, $urg_flag, $data, $hex, $number, $device, $run);


###[ MAIN PART ]###

# Load GUI interface
if($ARGV[0] eq "--gui")
{
    draw_gui();
}

# Show usage
elsif(($ARGV[0] eq "-?") || ($ARGV[0] eq "--help") || (scalar(@ARGV) == 0))
{
    print "Usage $0: [--gui] [--interactive] [--conf]\n\n";
    print "Use --gui to load the gui version,\n";
    print "--interactive to load the interactive shell interface and\n";
    print "--conf to load a config file.\n";
    print "--params will present to a full list of parameters\n\n";
}

# Show all parameters
elsif($ARGV[0] eq "--params")
{
    print "--protocol=[tcp|udp|icmp|arp]\n";
    print "--device=<dev>\n";
    print "--srcip=<ip>\n";
    print "--dstip=<ip>\n";
    print "--frag=<n>\n";
    print "--ttl=<n>\n";
    print "--srcport=<n>\n";
    print "--dstport=<n>\n";
    print "--seq=<n>\n";
    print "--ackseq=<n>\n";
    print "--win=<n>\n";
    print "--syn=[0|1]\n";
    print "--ack=[0|1]\n";
    print "--rst=[0|1]\n";
    print "--fin=[0|1]\n";
    print "--psh=[0|1]\n";
    print "--urg=[0|1]\n";
    print "--smac=<mac>\n";
    print "--dmac=<mac>\n";
    print "--arpop=[request|reply|revrequest|revreply|invrequest|invreply]\n";
    print "--icmptype=<n>\n";
    print "--icmpcode=<n>\n";
    print "--gateway=<ip>\n";
    print "--mtu=<n>\n";
    print "--data=<string>\n";
#    print "--hex\n";
    print "--number=<n>\n";
    print "--brute=[sport|dport|icmp]\n\n";
}

# We shall load a config file
elsif($ARGV[0] eq "--conf")
{
    print "Reading $ARGV[1]\n";
    $config = path::config::readcfg($ARGV[1]);
    run();
}

# Load interactive shell interface
elsif($ARGV[0] eq "--interactive")
{
    shell_interface();
}

# Load parameter driven shell interface
else
{
    my $brutemode;
    GetOptions ('protocol=s' => \$config->{'parameter'}->{'protocol'}, 
		'device=s' => \$config->{'parameter'}->{'device'},
		'srcip=s' => \$config->{'packet'}->{'ip'}->{'srcip'},
		'dstip=s' => \$config->{'packet'}->{'ip'}->{'dstip'},
		'frag=i' => \$config->{'packet'}->{'ip'}->{'frag'},
		'ttl=i' => \$config->{'packet'}->{'ip'}->{'ttl'},
		'icmptype=i' => \$config->{'packet'}->{'icmp'}->{'type'},
		'icmpcode=i' => \$config->{'packet'}->{'icmp'}->{'code'},
		'gateway=s' => \$config->{'packet'}->{'icmp'}->{'gateway'},
		'mtu=i' => \$config->{'packet'}->{'icmp'}->{'mtu'},
		'smac=s' => \$config->{'packet'}->{'arp'}->{'srcmac'},
		'dmac=s' => \$config->{'packet'}->{'arp'}->{'dstmac'},
		'arpop=s' => \$config->{'packet'}->{'arp'}->{'op'},
		'srcport=i' => \$config->{'packet'}->{'tcp'}->{'srcport'},
		'dstport=i' => \$config->{'packet'}->{'tcp'}->{'dstport'},
		'seq=i' => \$config->{'packet'}->{'tcp'}->{'seq'},
		'ackseq=i' => \$config->{'packet'}->{'tcp'}->{'ack'},
		'win=i' => \$config->{'packet'}->{'tcp'}->{'win'},
		'syn' => \$config->{'packet'}->{'tcp'}->{'flags'}->{'syn'},
		'ack' => \$config->{'packet'}->{'tcp'}->{'flags'}->{'ack'},
		'rst' => \$config->{'packet'}->{'tcp'}->{'flags'}->{'rst'},
		'fin' => \$config->{'packet'}->{'tcp'}->{'flags'}->{'fin'},
		'psh' => \$config->{'packet'}->{'tcp'}->{'flags'}->{'psh'},
		'urg' => \$config->{'packet'}->{'tcp'}->{'flags'}->{'urg'},
		'data=s' => \$config->{'packet'}->{'data'},
		'number=i' => \$config->{'parameter'}->{'number'},
		'brute=s' => \$brutemode);

    # Check config and send packets
    if($brutemode ne "")
    {
	if($brutemode eq "sport")
	{
	    $config->{'parameter'}->{'brute'}->{'srcport'} = 1;
	}
	elsif($brutemode eq "dport")
	{
	    $config->{'parameter'}->{'brute'}->{'dstport'} = 1;
	}
	elsif($brutemode eq "icmp")
	{
	    $config->{'parameter'}->{'brute'}->{'icmp'} = 1;
	}
	else
	{
	    die "Unkown brute mode $brutemode\n";
	}
    }

    if($config->{'parameter'}->{'protocol'} eq "udp")
    {
	$config->{'packet'}->{'udp'}->{'srcport'} = $config->{'packet'}->{'tcp'}->{'srcport'};
	$config->{'packet'}->{'udp'}->{'dstport'} = $config->{'packet'}->{'tcp'}->{'dstport'};
    }

    # Check the configuration
    die if check_cfg() == 1;

    # Send the packet(s)
    run();
}


###[ Subroutines ]###

# Get parameter from shell
sub shell_interface
{
	my $tmp;

        # General Configuration
	print "Give me a network device: ";
	$tmp = <STDIN>; chomp($tmp);
	$config->{'parameter'}->{'device'} = $tmp;

	print "Tell me the protocol (tcp/udp/icmp/arp): ";
	$tmp = <STDIN>;	chomp($tmp);
	if( (lc($tmp) ne "tcp") && (lc($tmp) ne "udp") && (lc($tmp) ne "icmp") && (lc($tmp) ne "arp") )
	{
	    die "Unknown protocol $tmp!\n";
	}
	else
	{
	    $config->{'parameter'}->{'protocol'} = lc($tmp);
	}

        # Configuring IP options
	print "Tell me the source ip: ";
	$tmp = <STDIN>; chomp($tmp);
	$config->{'packet'}->{'ip'}->{'srcip'} = $tmp;

	print "Tell me the destination ip: ";
	$tmp = <STDIN>; chomp($tmp);
	$config->{'packet'}->{'ip'}->{'dstip'} = $tmp;

	unless($config->{'parameter'}->{'protocol'} eq "arp")
	{
	    print "Give me the fragmentation offset: ";
	    $tmp = <STDIN>; chomp($tmp);
	    $config->{'packet'}->{'ip'}->{'frag'} = $tmp;

	    print "Time to live: ";
	    $tmp = <STDIN>; chomp($tmp);
	    $config->{'packet'}->{'ip'}->{'ttl'} = $tmp;
	}

        # Configuring ICMP options
	if($config->{'parameter'}->{'protocol'} eq "icmp")
	{
	    print "Bruteforce ICMP type and code? (y/n): ";
	    $tmp = <STDIN>; chomp($tmp);

	    if($tmp eq "y")
	    {
		$config->{'parameter'}->{'brute'}->{'icmp'} = 1;
	    }
	    else
	    {
		print "Tell me the ICMP-type: ";
		$tmp = <STDIN>; chomp($tmp);
		$config->{'packet'}->{'icmp'}->{'type'} = $tmp;
	    
		print "Tell me the ICMP-code: ";
		$tmp = <STDIN>; chomp($tmp);
		$config->{'packet'}->{'icmp'}->{'code'} = $tmp;
	    }

	    print "Give me the gateway: ";
	    $tmp = <STDIN>; chomp($tmp);
	    $config->{'packet'}->{'icmp'}->{'gateway'} = $tmp;
	    
	    print "Give me the MTU value: ";
	    $tmp = <STDIN>; chomp($tmp);
	    $config->{'packet'}->{'icmp'}->{'mtu'} = $tmp;
	}

        # Configuring ARP options
	elsif($config->{'protocol'} eq "arp")
	{
	    print "Give me the source MAC: ";
	    $tmp = <STDIN>; chomp($tmp);
	    $config->{'packet'}->{'arp'}->{'srcmac'} = $tmp;

	    print "Give me the destination MAC: ";
	    $tmp = <STDIN>; chomp($tmp);
	    $config->{'packet'}->{'arp'}->{'dstmac'} = $tmp;

	    my $brk = 1;

	    while($brk)
	    {
		print "Tell me the ARP operation type:\n";
		print "[reply|request|revreply|revrequest|invreply|invrequest]\n";
		print "choice: ";
		$tmp = <STDIN>;
		chomp $tmp;

		if( ($tmp eq "reply") || ($tmp eq "request") || ($tmp eq "revreply") || ($tmp eq "revrequest") || ($tmp eq "invreply") || ($tmp eq "invrequest") )
		{
		    $brk = 0;
		}
		else
		{
		    print "Wrong arp operation: $tmp!\n\n";
		}
	    }
	    
	    $config->{'packet'}->{'arp'}->{'op'} = $tmp;
	}

        # Configuring UDP options
	elsif($config->{'parameter'}->{'protocol'} eq "udp")
	{
	    print "Bruteforce source ports? (y/n): ";
	    $tmp = <STDIN>; chomp($tmp);

	    if($tmp eq "y")
	    {
		$config->{'parameter'}->{'brute'}->{'srcport'} = 1;
	    }
	    else
	    {
		print "Source port: ";
		$tmp = <STDIN>; chomp($tmp);
		$config->{'packet'}->{'udp'}->{'srcport'} = $tmp;
	    }

	    print "Bruteforce destination port? (y/n): ";
	    $tmp = <STDIN>; chomp($tmp);

	    if($tmp eq "y")
	    {
		$config->{'parameter'}->{'brute'}->{'dstport'} = 1;
	    }
	    else
	    {
		print "Destination port: ";
		$tmp = <STDIN>; chomp($tmp);
		$config->{'packet'}->{'udp'}->{'dstport'} = $tmp;
	    }
	}

	# TCP options
	elsif($config->{'parameter'}->{'protocol'} eq "tcp")
	{
	    print "Bruteforce source port? (y/n): ";
	    $tmp = <STDIN>; chomp($tmp);

	    if($tmp eq "y")
	    {
		$config->{'parameter'}->{'brute'}->{'srcport'} = 1;
	    }
	    else
	    {
		print "Source port: ";
		$tmp = <STDIN>; chomp($tmp);
		$config->{'packet'}->{'tcp'}->{'srcport'} = $tmp;
	    }

	    print "Bruteforce destination port? (y/n): ";
	    $tmp = <STDIN>; chomp($tmp);

	    if($tmp eq "y")
	    {
		$config->{'parameter'}->{'brute'}->{'dstport'} = 1;
	    }
	    else
	    {
		print "Destination port: ";
		$tmp = <STDIN>; chomp($tmp);
		$config->{'packet'}->{'tcp'}->{'dstport'} = $tmp;
	    }

	    print "Tell me the Sequence number: ";
	    $tmp = <STDIN>; chomp($tmp);

	    if($tmp eq "")
	    {
		$config->{'packet'}->{'tcp'}->{'seq'} = 1000000000;
	    }
	    else
	    {
		$config->{'packet'}->{'tcp'}->{'seq'} = $tmp;
	    }

	    print "Tell me the Acknowledgement number: ";
	    $tmp = <STDIN>; chomp($tmp);

	    if($tmp eq "")
	    {
		$config->{'packet'}->{'tcp'}->{'ack'} = 1000000000;
	    }
	    else
	    {
		$config->{'packet'}->{'tcp'}->{'ack'} = $tmp;
	    }
	    
	    print "Tell me the window size: ";
	    $tmp = <STDIN>; chomp($tmp);
	    $config->{'packet'}->{'tcp'}->{'win'} = $tmp;
	    
	    print "Give me the flags (0 == off, 1 == on).\n";
	    print "SYN: ";
	    $tmp = <STDIN>; chomp($tmp);
	    $config->{'packet'}->{'tcp'}->{'flags'}->{'syn'} = $tmp;
	    
	    print "ACK: ";
	    $tmp = <STDIN>; chomp($tmp);
	    $config->{'packet'}->{'tcp'}->{'flags'}->{'ack'} = $tmp;
	    
	    print "PSH: ";
	    $tmp = <STDIN>; chomp($tmp);
	    $config->{'packet'}->{'tcp'}->{'flags'}->{'psh'} = $tmp;
	    
	    print "RST: ";
	    $tmp = <STDIN>; chomp($tmp);
	    $config->{'packet'}->{'tcp'}->{'flags'}->{'rst'} = $tmp;
	    
	    print "FIN: ";
	    $tmp = <STDIN>; chomp($tmp);
	    $config->{'packet'}->{'tcp'}->{'flags'}->{'fin'} = $tmp;
	    
	    print "URG: ";
	    $tmp = <STDIN>; chomp($tmp);
	    $config->{'packet'}->{'tcp'}->{'flags'}->{'urg'} = $tmp;
	}

	unless($config->{'parameter'}->{'protocol'} eq "arp")
	{
	    print "Give me the payload: ";
	    $tmp = <STDIN>; chomp($tmp);
	    $config->{'packet'}->{'data'} = $tmp;
	}

	print "How much packets shall I send? ";
	$tmp = <STDIN>; chomp($tmp);
	$config->{'parameter'}->{'number'} = $tmp;

    # Check the config and send the packets afterwards
    return if check_cfg() == 1;
    run();
    print "\nAll done.\nHave phun! ;D\n";
}


# Creating and sending the packets
sub run
{
    my @packets;
    my $count = 0;
    $run->configure(-state => 'disabled', -text => 'Creating') if defined $run;
    $top->update if defined $top;

    print "--> Creating packets\n" unless $top;

    if( ($config->{'parameter'}->{'brute'}->{'srcport'}) && 
	($config->{'parameter'}->{'brute'}->{'dstport'}) )
    {
	push @packets, @{path::hijack::bruteforce($config,"ports")};
    }
    else
    {
	# Bruteforce TCP / UDP source port
	push @packets, @{path::hijack::bruteforce($config,"srcport")} if($config->{'parameter'}->{'brute'}->{'srcport'});

	# Bruteforce TCP / UDP destination port
	push @packets, @{path::hijack::bruteforce($config,"dstport")} if($config->{'parameter'}->{'brute'}->{'dstport'});
    
	# Bruteforce ICMP
	push @packets, @{path::hijack::bruteforce($config,"icmp")} if($config->{'parameter'}->{'brute'}->{'icmp'});
    }

    # Dont bruteforce anything
    unless( ($config->{'parameter'}->{'brute'}->{'srcport'}) || 
	    ($config->{'parameter'}->{'brute'}->{'dstport'}) || 
	    ($config->{'parameter'}->{'brute'}->{'icmp'}) || 
	    ($config->{'parameter'}->{'protocol'} eq "arp") )
    {
	push @packets, path::hijack::create_packet($config);
    }

    $run->configure(-state => 'disabled', -text => 'Sending') if defined $run;
    $top->update if defined $top;
    print "--> Sending packets" unless $top;

    my $percent_done = 0;
    my ($percent, $prog);
    my $flag = 0;

    # Tk progress bar
    if(defined $top)
    {
	$prog = $top->Toplevel;
	$prog->title('Status');
	$prog->configure(-background => 'black');
	my $title_frame = $prog->Frame()->grid();
	$title_frame->configure(-background => 'black');
	
	$title_frame->Label(-text => 'Sending packets',
			    -background => 'black',
			    -foreground => 'green',
			    -border => 0)->grid(-row => 1, -pady => 5);

	my $status_frame = $prog->Frame()->grid();
	$status_frame->configure(-background => 'black');
	
	$percent = $status_frame->Label(-text => $percent_done."%",
					-background => 'black',
					-foreground => 'green',
					-border => 0)->grid(-row => 1, -column => 1, -pady => 20);

	$status_frame->ProgressBar(-from => 0,
				   -to => 100,
				   -colors => [0,'green'],
				   -variable => \$percent_done)->grid(-row => 1, -column => 2, -pady => 20);

	my $button_frame = $prog->Frame()->grid();
	$button_frame->Button(-text => 'Quit',
			      -activebackground => 'black',
			      -activeforeground => 'red',
			      -borderwidth => 4,
			      -border => 0,
			      -relief => 'raised',
			      -command => sub { @packets = []; $run->configure(-state => 'normal', -text => 'Run packet! Run!!') if defined $run; $flag = 1; $prog->destroy; })->grid(-row => 1, -column => 1, -padx => 25);
    }

    my $num_all_packets = scalar(@packets) * $config->{'parameter'}->{'number'};

    # Send the packets
    while(scalar(@packets)>0)
    {
	my $packet = shift(@packets);

	for(my $i=1; $i<=$config->{'parameter'}->{'number'}; $i++)
	{
#	    eval { $packet->send(0.25,1); };
	    eval { $packet->send(0,1); };
	    print "." unless $top;
	    $count++;
	    $percent_done = int(($count / $num_all_packets) * 100);
	
	    if(defined $top)
	    {
		eval { $percent->configure(-text => $percent_done."%"); };
		$top->update;
		eval{ $prog->update if defined $prog; };
	    }
	}
    }

    # Create and send the packet
    if($config->{'parameter'}->{'protocol'} eq "arp")
    {
	$config->{'packet'}->{'ip'}->{'srcip'} = '0' unless defined $config->{'packet'}->{'ip'}->{'srcip'};
	$config->{'packet'}->{'arp'}->{'srcmac'} = '0' unless defined $config->{'packet'}->{'arp'}->{'srcmac'};
	$config->{'packet'}->{'arp'}->{'dstmac'} = '0' unless defined $config->{'packet'}->{'arp'}->{'dstmac'};

	for(my $i=1; $i<=$config->{'parameter'}->{'number'}; $i++)
	{
	    print "." unless $top;
	    $count++;
	    $percent_done = int(($count / $config->{'parameter'}->{'number'}) * 100);
		
	    if(defined $top)
	    {
		$percent->configure(-text => $percent_done."%");
		$top->update;
		$prog->update if defined $prog;
	    }

	    Net::ARP::send_packet($config->{'parameter'}->{'device'},       # Interface
				   $config->{'packet'}->{'ip'}->{'srcip'},   # Source IP
				   $config->{'packet'}->{'ip'}->{'dstip'},   # Destination IP
				   $config->{'packet'}->{'arp'}->{'srcmac'}, # Source MAC
				   $config->{'packet'}->{'arp'}->{'dstmac'}, # Destination IP	
				   $config->{'packet'}->{'arp'}->{'op'});    # ARP operation
	}
    }

    # Print the result
    print " [Done]\n" unless $top;
    eval { $prog->destroy() if $flag == 0; };
    print "--> $count packets were send over the wire.\n" unless $top;
    $run->configure(-state => 'normal', -text => 'Run packet! Run!!') if defined $run;
}


###[ The GUI code ]###

# Draw the GUI
sub draw_gui
{
    select_proto();
    MainLoop();
}


# Create the Main window depending on the selected protocol
sub create_win
{
    # Destroy protocol selection window
    $askproto->destroy;

    # The main window
    $top = MainWindow->new(-background => 'black', -foreground => 'green');
    $top->title('IP-Packet -- A Packetgenerator written in Perl');
    $top->option(add => '*background', 'black');
    $top->option(add => '*foreground', 'green');

    # Menu bar
    my $menu = $top->Menu(-type => 'menubar');
    my $conf = $menu->cascade('-label' => 'Configure', '-tearoff' => 0);
    $conf->configure(-activebackground => 'black',
		     -activeforeground => 'red');

    $conf->command('-label' => 'Select another protocol',
		   -activebackground => 'black',
		   -activeforeground => 'red',
		   -command => \&select_proto);

    $conf->command('-label' => 'Read Configfile',
		   -activebackground => 'black',
		   -activeforeground => 'red',
		   -command => \&opencfgdialog);

    $conf->command('-label' => 'Save Configuration',
		   -activebackground => 'black',
		   -activeforeground => 'red',
		   -command => \&savecfgdialog);

    my $about = $menu->cascade('-label' => 'About', '-tearoff' => 0);
    $about->configure(-activebackground => 'black',
		      -activeforeground => 'red');

    $about->command('-label' => 'About this tool',
		    -activebackground => 'black',
		    -activeforeground => 'red',
		    -command => \&about);

    $about->command('-label' => 'Heeelp me',
		    -activebackground => 'black',
		    -activeforeground => 'red',
		    -command => \&help);

    $top->configure(-menu => $menu);

    my $title = $top->Frame(-background => 'black')->grid();

    $title->Label(-text => 'IP-Packet -- The ultimative packetgenerator',
		  -border => 0,
		  -relief => 'groove',
		  -anchor => 'n')->grid(-pady => 10);

    my $prototmp = uc($config->{'parameter'}->{'protocol'});
    $title->Label(-text => "Create a $prototmp / IP packet",
		  -border => 0)->grid(-pady => 10);

    my $content = $top->Frame(-background => 'black')->grid(-pady => 10, -ipadx => 5);


    # IP options 
    $content->Label(-text => 'Source IP: ',
		    -border => 0)->grid(-row => 1, -column => 1, -pady => 5);
    
    $spoof = $content->Entry(-background => '#3C3C3C',
			     -textvariable => \$config->{'packet'}->{'ip'}->{'srcip'})->grid(-row => 1, -column => 2, -pady => 5);

    $content->Label(-text => 'Destination IP: ',
		    -border => 0)->grid(-row => 2, -column => 1, -pady => 5);

    $target = $content->Entry(-background => '#3C3C3C',
			      -textvariable => \$config->{'packet'}->{'ip'}->{'dstip'})->grid(-row => 2, -column => 2, -pady => 5);
    
    if($config->{'parameter'}->{'protocol'} ne "arp")
    {
	$content->Label(-text => 'Fragmentation Offset: ',
			-border => 0)->grid(-row => 3, -column => 1, -pady => 5);

	$frag = $content->Entry(-background => '#3C3C3C',
				-textvariable => \$config->{'packet'}->{'ip'}->{'frag'})->grid(-row => 3, -column => 2, -pady => 5);

	$content->Label(-text => 'Time to live: ',
			-border => 0)->grid(-row => 4, -column => 1, -pady => 5);

	$ttl = $content->Entry(-background => '#3C3C3C',
			       -textvariable => \$config->{'packet'}->{'ip'}->{'ttl'})->grid(-row => 4, -column => 2, -pady => 5);
    }


    # ARP options
    if($config->{'parameter'}->{'protocol'} eq "arp")
    {
	$content->Label(-text => 'Source MAC: ',
			-border => 0)->grid(-row => 5, -column => 1, -pady => 5);

	$smac = $content->Entry(-background => '#3C3C3C',
				-textvariable => \$config->{'packet'}->{'arp'}->{'srcmac'})->grid(-row => 5, -column => 2, -pady => 5);

	my ($tmp,$errbuf);
	Net::ARP::get_mac(Net::Pcap::lookupdev(\$errbuf),$tmp);
	$smac->delete(0,'end');
	$smac->insert(0,$tmp);

	$content->Label(-text => 'Destination MAC: ',
			-border => 0)->grid(-row => 6, -column => 1, -pady => 5);

	$dmac = $content->Entry(-background => '#3C3C3C',
				-textvariable => \$config->{'packet'}->{'arp'}->{'dstmac'})->grid(-row => 6, -column => 2, -pady => 5);

	$dmac->delete(0,'end');
	$dmac->insert(0,'ff:ff:ff:ff:ff:ff');
    }



    # ICMP options
    if($config->{'parameter'}->{'protocol'} eq "icmp")
    {
	$content->Label(-text => 'ICMP-Type: ',
			-border => 0)->grid(-row => 5, -column => 1, -pady => 5);

	$icmptype = $content->Entry(-background => '#3C3C3C',
				    -textvariable => \$config->{'packet'}->{'icmp'}->{'type'})->grid(-row => 5, -column => 2, -pady => 5);

	$content->Checkbutton(-variable => \$brute_icmp,
			      -text => 'Bruteforce',
			      -onvalue => 1,
			      -offvalue => 0,
			      -activebackground => 'black',
			      -activeforeground => 'red')->grid(-row => 5, -column => 3, -pady => 5);

	$content->Label(-text => 'ICMP-Code: ',
			-border => 0)->grid(-row => 6, -column => 1, -pady => 5);

	$icmpcode = $content->Entry(-background => '#3C3C3C',
				    -textvariable => \$config->{'packet'}->{'icmp'}->{'code'})->grid(-row => 6, -column => 2, -pady => 5);

	$content->Checkbutton(-variable => \$brute_icmp,
			      -text => 'Bruteforce',
			      -onvalue => 1,
			      -offvalue => 0,
			      -activebackground => 'black',
			      -activeforeground => 'red')->grid(-row => 6, -column => 3, -pady => 5);

	$content->Label(-text => 'Gateway: ',
			-border => 0)->grid(-row => 7, -column => 1, -pady => 5);

	$gateway = $content->Entry(-background => '#3C3C3C',
				   -textvariable => \$config->{'packet'}->{'icmp'}->{'gateway'})->grid(-row => 7, -column => 2, -pady => 5);

	$content->Label(-text => 'MTU: ',
			-border => 0)->grid(-row => 8, -column => 1, -pady => 5);

	$mtu = $content->Entry(-background => '#3C3C3C',
			       -textvariable => \$config->{'packet'}->{'icmp'}->{'mtu'})->grid(-row => 8, -column => 2, -pady => 5);
    }




    # TCP / UDP option
    if( ($config->{'parameter'}->{'protocol'} eq "tcp") || 
	($config->{'parameter'}->{'protocol'} eq "udp") )
    {
	$content->Label(-text => 'Sourceport: ',
			-border => 0)->grid(-row => 5, -column => 1, -pady => 5);

	$sport = $content->Entry(-background => '#3C3C3C',
				 -textvariable => \$config->{'packet'}->{$config->{'parameter'}->{'protocol'}}->{'srcport'})->grid(-row => 5, -column => 2, -pady => 5);

	$content->Checkbutton(-variable => \$brute_sport,
			      -text => 'Bruteforce',
			      -onvalue => 1,
			      -offvalue => 0,
			      -activebackground => 'black',
			      -activeforeground => 'red')->grid(-row => 5, -column => 3, -pady => 5);

	$content->Label(-text => 'Destinationport: ',
			-border => 0)->grid(-row => 6, -column => 1, -pady => 5);

	$dport = $content->Entry(-background => '#3C3C3C',
				 -textvariable => \$config->{'packet'}->{$config->{'parameter'}->{'protocol'}}->{'dstport'})->grid(-row => 6, -column => 2, -pady => 5);
	
	$content->Checkbutton(-variable => \$brute_dport,
			      -text => 'Bruteforce',
			      -onvalue => 1,
			      -offvalue => 0,
			      -activebackground => 'black',
			      -activeforeground => 'red')->grid(-row => 6, -column => 3, -pady => 5);



        # TCP only options
	if($config->{'parameter'}->{'protocol'} eq "tcp")
	{
	    $content->Label(-text => 'Sequence number: ',
			    -border => 0)->grid(-row => 7, -column => 1, -pady => 5);

	    $seqnum = $content->Entry(-background => '#3C3C3C',
				      -textvariable => \$config->{'packet'}->{'tcp'}->{'seq'})->grid(-row => 7, -column => 2, -pady => 5);
	    
	    $content->Label(-text => 'Acknowledgement number: ',
			    -border => 0)->grid(-row => 8, -column => 1, -pady => 5);

	    $acknum = $content->Entry(-background => '#3C3C3C',
				      -textvariable => \$config->{'packet'}->{'tcp'}->{'ack'})->grid(-row => 8, -column => 2, -pady => 5);

	    $content->Label(-text => 'Window size: ',
			    -border => 0)->grid(-row => 9, -column => 1, -pady => 5);

	    $win = $content->Entry(-background => '#3C3C3C',
				   -textvariable => \$config->{'packet'}->{'tcp'}->{'win'})->grid(-row => 9, -column => 2, -pady => 5);

	    my $flaglabel = $top->Frame()->grid();

	    $flaglabel->Label(-text => 'Now select the TCP flags: ',
			      -border => 0)->grid(-pady => 10);

	    my $flags = $top->Frame()->grid();

            # Default maessig sind alle flags aus
	    $syn_flag = 0;
	    $ack_flag = 0;
	    $rst_flag = 0;
	    $fin_flag = 0;
	    $psh_flag = 0;
	    $urg_flag = 0;

	    $syn = $flags->Checkbutton(-variable => \$syn_flag,
				       -text => 'SYN',
				       -onvalue => 1,
				       -offvalue => 0,
				       -activebackground => 'black',
				       -activeforeground => 'red')->grid(-row => 1, -column => 1, -ipadx => 2); 

	    $ack = $flags->Checkbutton(-variable => \$ack_flag,
				       -text => 'ACK',
				       -onvalue => 1,
				       -offvalue => 0,
				       -activebackground => 'black',
				       -activeforeground => 'red')->grid(-row => 1, -column => 2, -ipadx => 2);
	    
	    $fin = $flags->Checkbutton(-variable => \$fin_flag,
				       -text => 'FIN',
				       -onvalue => 1,
				       -offvalue => 0,
				       -activebackground => 'black',
				       -activeforeground => 'red')->grid(-row => 1, -column => 3, -ipadx => 2);

	    $rst = $flags->Checkbutton(-variable => \$rst_flag,
				       -text => 'RST',
				       -onvalue => 1,
				       -offvalue => 0,
				       -activebackground => 'black',
				       -activeforeground => 'red')->grid(-row => 1, -column => 4, -ipadx => 2);

	    $psh = $flags->Checkbutton(-variable => \$psh_flag,
				       -text => 'PSH',
				       -onvalue => 1,
				       -offvalue => 0,
				       -activebackground => 'black',
				       -activeforeground => 'red')->grid(-row => 1, -column => 5, -ipadx => 2);

	    $urg = $flags->Checkbutton(-variable => \$urg_flag,
				       -text => 'URG',
				       -onvalue => 1,
				       -offvalue => 0,
				       -activebackground => 'black',
				       -activeforeground => 'red')->grid(-row => 1, -column => 6, -ipadx => 2);
	}
    }



    # General options
    unless($config->{'parameter'}->{'protocol'} eq "arp")
    {
	$content->Label(-text => 'Packet data: ',
			-border => 0)->grid(-row => 10, -column => 1, -pady => 5);

	$data = $content->Entry(-background => '#3C3C3C',
				-textvariable => \$config->{'packet'}->{'data'})->grid(-row => 10, -column => 2, -pady => 5);
    }

    $content->Label(-text => 'Number of packets:  ',
		    -border => 0)->grid(-row => 11, -column => 1, -pady => 5);

    $number = $content->Entry(-background => '#3C3C3C',
			      -textvariable => \$config->{'parameter'}->{'number'})->grid(-row => 11, -column => 2, -pady => 5);

    $content->Label(-text => 'Device:  ',
		    -border => 0)->grid(-row => 12, -column => 1, -pady => 5);

    $device = $content->Entry(-background => '#3C3C3C',
			      -textvariable => \$config->{'parameter'}->{'device'})->grid(-row => 12, -column => 2, -pady => 5);
    my $errbuf;
    $device->delete(0,'end');
    $device->insert(0,Net::Pcap::lookupdev(\$errbuf));


    if($config->{'parameter'}->{'protocol'} eq "arp")
    {

	$content->Label(-text => 'ARP operation: ',
			-border => 0,
			-relief => 'groove',
			-anchor => 'n')->grid(-row => 13, -column => 1, -pady => 5);

	$config->{'packet'}->{'arp'}->{'op'} = "reply";
	my $arpmenu = $content->Optionmenu(-options => ['reply','request','revresponse','revrequest','invreply','invrequest'],
					   -textvariable => \$config->{'packet'}->{'arp'}->{'op'})->grid(-row => 13, -column => 2, -pady => 5);
    }

    # The taskbar    
    my $taskbar = $top->Frame(-background => 'black')->grid(-pady => 20);
    $run = $taskbar->Button(-text => 'Run Packet! Run!!',
			    -activebackground => 'black',
			    -activeforeground => 'red',
			    -borderwidth => 4,
			    -border => 0,
			    -relief => 'raised',
			    -command => \&get_and_run)->grid(-row => 1, -column => 1, -padx => 25);
    
    my $quit = $taskbar->Button(-text => 'Quit that shit',
				-activebackground => 'black',
				-activeforeground => 'red',
				-borderwidth => 4,
				-border => 0,
				-relief => 'raised',
				-command => sub { exit(0); })->grid(-row => 1, -column => 2, -padx => 25);
}


# Select the protocol
sub select_proto
{
    $top->destroy if defined $top;

    $askproto = MainWindow->new(-background => 'black', -foreground => 'green');
    $askproto->title('Select the protocol');
    $askproto->option(add => '*background', 'black');
    $askproto->option(add => '*foreground', 'green');

    $askproto->Label(-text => 'Select a protocol',
		     -border => 0)->pack(-side => 'top', -pady => 10);


    my $up = $askproto->Frame->pack(-side => 'top', -pady => 5);
    my $down = $askproto->Frame->pack(-side => 'bottom', -pady => 5);

    # Standard protocol is TCP
    $config->{'parameter'}->{'protocol'} = "tcp";

    my $tcp = $up->Radiobutton(-variable => \$config->{'parameter'}->{'protocol'},
			       -text => 'TCP',
			       -value => 'tcp',
			       -activebackground => 'black',
			       -activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);

    my $udp = $up->Radiobutton(-variable => \$config->{'parameter'}->{'protocol'},
			       -text => 'UDP',
			       -value => 'udp',
			       -activebackground => 'black',
			       -activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);

    my $arp = $up->Radiobutton(-variable => \$config->{'parameter'}->{'protocol'},
			       -text => 'ARP',
			       -value => 'arp',
			       -activebackground => 'black',
			       -activeforeground => 'red')->pack(-side => 'right', -pady => 5, -padx => 5);


    my $icmp = $up->Radiobutton(-variable => \$config->{'parameter'}->{'protocol'},
				-text => 'ICMP',
				-value => 'icmp',
				-activebackground => 'black',
				-activeforeground => 'red')->pack(-side => 'right', -pady => 5, -padx => 5);


    my $submit = $down->Button(-text => 'OK',
			       -activebackground => 'black',
			       -activeforeground => 'red',
			       -borderwidth => 4,
			       -border => 0,
			       -command => \&create_win)->pack(-pady => 5);
    
}



# Help dialog
sub help
{
    my $helpwin = $top->Toplevel(-foreground => 'red', -background => 'black');
    $helpwin->title('Dont got r00t?? :-p');
    $helpwin->option(add => '*background', 'black');
    $helpwin->option(add => '*foreground', 'green');

    $helpwin->Label(-text => 'If you need help, please read the documents located in docs',
		    -border => 0)->pack(-pady => 5);
    
    my $downtown = $helpwin->Frame()->pack(-pady => 20);
    $downtown->Button(-text => 'Close',
		      -activebackground => 'black',
		      -activeforeground => 'red',
		      -borderwidth => 5,
		      -command => sub { destroy $helpwin })->pack();
}


# Load a config file
sub opencfgdialog
{
    my $f = $top->FileSelect(-directory => ".",
			     -filter => "*");

    my $cfgfile = $f->Show();
    return if $cfgfile eq "";
    my $oldprotocol = $config->{'parameter'}->{'protocol'};
    $config = path::config::readcfg($cfgfile);


    # No protocol at all?
    if($config->{'parameter'}->{'protocol'} eq "")
    {
	show_error('The configuration contains no protocol!\n');
	$config->{'parameter'}->{'protocol'} = $oldprotocol;
	return;
    }

    # Protoocol has changed?
    elsif($oldprotocol ne $config->{'parameter'}->{'protocol'})
    {
	show_error('The configuration file contains the wrong protocol!\n');
	$config->{'parameter'}->{'protocol'} = $oldprotocol;
	return;
    }

    $device->delete(0,'end');
    $device->insert('0',"$config->{'parameter'}->{'device'}");

    $spoof->delete(0,'end');
    $spoof->insert('0',"$config->{'packet'}->{'ip'}->{'srcip'}");

    $target->delete(0,'end');
    $target->insert('0',"$config->{'packet'}->{'ip'}->{'dstip'}");
    
    if($config->{'parameter'}->{'protocol'} ne "arp")
    {
	$frag->delete(0,'end');
	$frag->insert('0',"$config->{'packet'}->{'ip'}->{'frag'}");
	$ttl->delete(0,'end');
	$ttl->insert('0',"$config->{'packet'}->{'ip'}->{'ttl'}");
    }

    if($config->{'parameter'}->{'protocol'} eq "arp")
    {
	$smac->delete(0,'end');
	$smac->insert('0',$config->{'packet'}->{'arp'}->{'srcmac'});
	
	$dmac->delete(0,'end');
	$dmac->insert('0',$config->{'packet'}->{'arp'}->{'dstmac'});
    }
    elsif($config->{'parameter'}->{'protocol'} eq "icmp")
    {
	$icmptype->delete(0,'end');
	$icmptype->insert('0',"$config->{'packet'}->{'icmp'}->{'type'}");
	$icmpcode->delete(0,'end');
	$icmpcode->insert('0',"$config->{'packet'}->{'icmp'}->{'code'}");
	$gateway->delete(0,'end');
	$gateway->insert('0',"$config->{'packet'}->{'icmp'}->{'gateway'}");
	$mtu->delete(0,'end');
	$mtu->insert('0',"$config->{'packet'}->{'icmp'}->{'mtu'}");
    }
    else
    {
	$sport->delete(0,'end');
	$sport->insert('0',"$config->{'packet'}->{$config->{'parameter'}->{'protocol'}}->{'srcport'}");
	$dport->delete(0,'end');
	$dport->insert('0',"$config->{'packet'}->{$config->{'parameter'}->{'protocol'}}->{'dstport'}");

	if($config->{'parameter'}->{'protocol'} eq "tcp")
	{
	    $seqnum->delete(0,'end');
	    $seqnum->insert('0',"$config->{'packet'}->{'tcp'}->{'seq'}");
	    $acknum->delete(0,'end');
	    $acknum->insert('0',"$config->{'packet'}->{'tcp'}->{'ack'}");
	    $win->delete(0,'end');
	    $win->insert('0',"$config->{'packet'}->{'tcp'}->{'win'}");
    
	    $syn->deselect();
	    $ack->deselect();
	    $psh->deselect();
	    $fin->deselect();
	    $rst->deselect();
	    $urg->deselect();

	    $syn->select if($config->{'packet'}->{'tcp'}->{'flags'}->{'syn'});
	    $ack->select() if($config->{'packet'}->{'tcp'}->{'flags'}->{'ack'});
	    $psh->select() if($config->{'packet'}->{'tcp'}->{'flags'}->{'psh'});
	    $rst->select() if($config->{'packet'}->{'tcp'}->{'flags'}->{'rst'});
	    $fin->select() if($config->{'packet'}->{'tcp'}->{'flags'}->{'fin'});
	    $urg->select() if($config->{'packet'}->{'tcp'}->{'flags'}->{'urg'});
	}
    }

    if($config->{'parameter'}->{'protocol'} ne "arp")
    {
	$data->delete(0,'end');
	$data->insert('0',"$config->{'packet'}->{'data'}");
    }

    $number->delete(0,'end');
    $number->insert('0',"$config->{'parameter'}->{'number'}");

    $top->update();
}


# Save configuration to file
sub savecfgdialog
{
    get_cfg();
    return if check_cfg() == 1;
    my $f = $top->FileSelect(-directory => ".",
			     -filter => "*");
    my $cfgfile = $f->Show();
    return if $cfgfile eq "";
    path::config::writecfg($config,$cfgfile);
}


# About dialog
sub about
{
    my $aboutwin = $top->Toplevel(-background => 'black', -foreground => 'red');
    $aboutwin->title('About this cool tool ;)');
    $aboutwin->option(add => '*background', 'black');
    $aboutwin->option(add => '*foreground', 'red');

    $aboutwin->Label(-text => 'IP-Packet-- An advanced packetgenerator written in Perl',
		     -border => 0)->pack(-pady => 5);

    $aboutwin->Label(-text => 'Programmed by Bastian Ballmann',
		     -border => 0)->pack(-padx => 10);

    $aboutwin->Label(-text => 'Last Update 24.07.2004',
		     -border => 0)->pack(-pady => 5);

    my $downtown = $aboutwin->Frame()->pack(-pady => 20);
    $downtown->Button(-text => 'Just close it!',
		      -foreground => 'green',
		      -activebackground => 'black',
		      -activeforeground => 'red',
		      -borderwidth => 5,
		      -command => sub { destroy $aboutwin})->pack();
}


# Read the users input (Tk Entries)
sub get_cfg
{
    my $tmp;
    $config->{'parameter'}->{'brute'}->{'srcport'} = $brute_sport;
    $config->{'parameter'}->{'brute'}->{'dstport'} = $brute_dport;
    $config->{'parameter'}->{'brute'}->{'icmp'} = $brute_icmp;
    $tmp = $device->get; $config->{'parameter'}->{'device'} = $tmp;
    $tmp = $spoof->get; $config->{'packet'}->{'ip'}->{'srcip'} = $tmp;
    $tmp = $target->get; $config->{'packet'}->{'ip'}->{'dstip'} = $tmp;

    if($config->{'parameter'}->{'protocol'} ne "arp")
    {	
	$tmp = $frag->get; $config->{'packet'}->{'ip'}->{'frag'} = $tmp;
	$tmp = $ttl->get; $config->{'packet'}->{'ip'}->{'ttl'} = $tmp;
	$tmp = $data->get; $config->{'packet'}->{'data'} = $tmp;
    }

    if($config->{'parameter'}->{'protocol'} eq "arp")
    {
	$tmp = $smac->get; $config->{'packet'}->{'arp'}->{'srcmac'} = $tmp;
	$tmp = $dmac->get; $config->{'packet'}->{'arp'}->{'dstmac'} = $tmp;
    }
    elsif($config->{'parameter'}->{'protocol'} eq "icmp")
    {
	$tmp = $icmptype->get; $config->{'packet'}->{'icmp'}->{'type'} = $tmp;
	$tmp = $icmpcode->get; $config->{'packet'}->{'icmp'}->{'code'} = $tmp;
	$tmp = $mtu->get; $config->{'packet'}->{'icmp'}->{'mtu'} = $tmp;
	$tmp = $gateway->get; $config->{'packet'}->{'icmp'}->{'gateway'} = $tmp;
    }
    else
    {
	$tmp = $sport->get; $config->{'packet'}->{$config->{'parameter'}->{'protocol'}}->{'srcport'} = $tmp;
	$tmp = $dport->get; $config->{'packet'}->{$config->{'parameter'}->{'protocol'}}->{'dstport'} = $tmp;

	if($config->{'parameter'}->{'protocol'} eq "tcp")
	{
	    $tmp = $seqnum->get; $config->{'packet'}->{'tcp'}->{'seq'} = $tmp;
	    $tmp = $acknum->get; $config->{'packet'}->{'tcp'}->{'ack'} = $tmp;
	    $tmp = $win->get; $config->{'packet'}->{'tcp'}->{'win'} = $tmp;
	    $config->{'packet'}->{'tcp'}->{'flags'}->{'syn'} = $syn_flag;
	    $config->{'packet'}->{'tcp'}->{'flags'}->{'ack'} = $ack_flag;
	    $config->{'packet'}->{'tcp'}->{'flags'}->{'fin'} = $fin_flag;
	    $config->{'packet'}->{'tcp'}->{'flags'}->{'rst'} = $rst_flag;
	    $config->{'packet'}->{'tcp'}->{'flags'}->{'psh'} = $psh_flag;
	    $config->{'packet'}->{'tcp'}->{'flags'}->{'urg'} = $urg_flag;
	}
    }

    $tmp = $number->get; $config->{'parameter'}->{'number'} = $tmp;
}


# Get config and send packets
sub get_and_run
{
    get_cfg();
    return if check_cfg() == 1;
    run();
}


# Check the users input and start sending packets
sub check_cfg
{
    # Default values
    $config->{'packet'}->{'ip'}->{'frag'} = 0 if $config->{'packet'}->{'ip'}->{'frag'} eq "";
    $config->{'packet'}->{'tcp'}->{'seq'} = 1000000000 if $config->{'packet'}->{'tcp'}->{'seq'} eq "";
    $config->{'packet'}->{'tcp'}->{'ack'} = 1000000000 if $config->{'packet'}->{'tcp'}->{'ack'} eq "";
    $config->{'packet'}->{'ip'}->{'ttl'} = "124" if $config->{'packet'}->{'ip'}->{'ttl'} eq "";
    $config->{'packet'}->{'tcp'}->{'win'} = "1024" if $config->{'packet'}->{'tcp'}->{'win'} eq "";
    $config->{'parameter'}->{'number'} = 1 if $config->{'parameter'}->{'number'} eq "";
    my $errbuf;
    $config->{'parameter'}->{'device'} = Net::Pcap::lookupdev(\$errbuf) if $config->{'parameter'}->{'device'} eq "";
    
    # No or wrong protocol?
    if( ($config->{'parameter'}->{'protocol'} ne "tcp") &&
	($config->{'parameter'}->{'protocol'} ne "udp") &&
	($config->{'parameter'}->{'protocol'} ne "icmp") &&
	($config->{'parameter'}->{'protocol'} ne "arp") )
    {
	show_error("Wrong protocol " . $config->{'parameter'}->{'protocol'} . "\n"); 
	return 1;
    }

    # Check IP addresses
    if( (length($config->{'packet'}->{'ip'}->{'srcip'}) == 0) || 
	(path::config::check_ip($config->{'packet'}->{'ip'}->{'srcip'}) == 1) )
    {
	show_error("Bad source IP address " . $config->{'packet'}->{'ip'}->{'srcip'} . "\n"); 
	return 1;
    }

    if( (length($config->{'packet'}->{'ip'}->{'dstip'}) == 0) || 
	(path::config::check_ip($config->{'packet'}->{'ip'}->{'dstip'}) == 1) )
    {
	show_error("Bad destination IP address " . $config->{'packet'}->{'ip'}->{'dstip'} . "\n"); 
	return 1;
    }

    # Check MAC addresses
    if($config->{'parameter'}->{'protocol'} eq "arp")
    {
	if(path::config::check_mac($config->{'packet'}->{'arp'}->{'srcmac'}) == 1)
	{
	    show_error("Bad source MAC address " . $config->{'packet'}->{'arp'}->{'srcmac'} . "\n"); 
	    return 1;
	}

	if(path::config::check_mac($config->{'packet'}->{'arp'}->{'dstmac'}) == 1)
	{
	    show_error("Bad destination MAC address " . $config->{'packet'}->{'arp'}->{'dstmac'} . "\n"); 
	    return 1;
	}

	if( ($config->{'packet'}->{'arp'}->{'op'} ne "request") && 
	    ($config->{'packet'}->{'arp'}->{'op'} ne "reply") &&
	    ($config->{'packet'}->{'arp'}->{'op'} ne "revrequest") &&
	    ($config->{'packet'}->{'arp'}->{'op'} ne "revreply") &&
	    ($config->{'packet'}->{'arp'}->{'op'} ne "invrequest") &&
	    ($config->{'packet'}->{'arp'}->{'op'} ne "invreply") )
	{
	    show_error("Invalid ARP operation " . $config->{'packet'}->{'arp'}->{'op'} . "\n"); 
	    return 1;
	}
    }

    # Check port numbers
    if( ($config->{'parameter'}->{'protocol'} eq "tcp") || 
	($config->{'parameter'}->{'protocol'} eq "udp") )
    {
	if( ($config->{'parameter'}->{'brute'}->{'srcport'} != 1) && 
	    (($config->{'packet'}->{$config->{'parameter'}->{'protocol'}}->{'srcport'} <= 0) || 
	     ($config->{'packet'}->{$config->{'parameter'}->{'protocol'}}->{'srcport'} > 65536)) )
	{
	    show_error("Bad source port " . $config->{'packet'}->{$config->{'parameter'}->{'protocol'}}->{'srcport'} . "\n"); 
	    return 1;
	}

	if( ($config->{'parameter'}->{'brute'}->{'dstport'} != 1) && 
	    (($config->{'packet'}->{$config->{'parameter'}->{'protocol'}}->{'dstport'} <= 0) || 
	     ($config->{'packet'}->{$config->{'parameter'}->{'protocol'}}->{'dstport'} > 65536)) )
	{
	    show_error("Bad destination port " . $config->{'packet'}->{$config->{'parameter'}->{'protocol'}}->{'dstport'} . "\n"); 
	    return 1;
	}
    }

    if($config->{'parameter'}->{'protocol'} ne "arp")
    {
	# Check TTL
	if($config->{'packet'}->{'ip'}->{'ttl'} !~ /\d+/)
	{
	    show_error("Bad TTL " . $config->{'packet'}->{'ip'}->{'ttl'} . "\n"); 
	    return 1;
	}

        # Check fragmentation offset
	if($config->{'packet'}->{'ip'}->{'frag'} !~ /\d+/)
	{
	    show_error("Bad fragmentation offset " . $config->{'packet'}->{'ip'}->{'frag'} . "\n"); 
	    return 1;
	}
    }

    if($config->{'parameter'}->{'protocol'} eq "tcp")
    {
	# Check sequence and acknowledgement numbers
	if($config->{'packet'}->{'tcp'}->{'seq'} !~ /\d{10}/)
	{
	    show_error("Bad sequence number " . $config->{'packet'}->{'tcp'}->{'seq'} . "\n"); 
	    return 1;
	}

	if($config->{'packet'}->{'tcp'}->{'ack'} !~ /\d{10}/)
	{
	    show_error("Bad sequence number " . $config->{'packet'}->{'tcp'}->{'ack'} . "\n"); 
	    return 1;
	}

	# Check window size
	if($config->{'packet'}->{'tcp'}->{'win'} !~ /\d+/)
	{
	    show_error("Bad window size " . $config->{'packet'}->{'tcp'}->{'win'} . "\n"); 
	    return 1;
	}
    }

    if($config->{'parameter'}->{'protocol'} eq "icmp")
    {
	# Check ICMP type and code
	if( ($config->{'packet'}->{'icmp'}->{'type'} !~ /\d+/) && 
	    ($brute_icmp != 1) )
	{
	    show_error("Bad ICMP type " . $config->{'packet'}->{'icmp'}->{'type'} . "\n"); 
	    return 1;
	}

	if( ($config->{'packet'}->{'icmp'}->{'code'} !~ /\d+/) && 
	    ($brute_icmp != 1) )
	{
	    show_error("Bad ICMP type " . $config->{'packet'}->{'icmp'}->{'code'} . "\n"); 
	    return 1;
	}

	# Check gateway IP address
	if( (length($config->{'packet'}->{'icmp'}->{'gateway'}) > 0) && 
	    (path::config::check_ip($config->{'packet'}->{'icmp'}->{'gateway'}) == 1) )
	{
	    show_error("Bad gateway IP address " . $config->{'packet'}->{'icmp'}->{'gateway'} . "\n"); 
	    return 1;
	}

	# Check MTU
	if( (length($config->{'packet'}->{'icmp'}->{'mtu'}) > 0) && 
	    ($config->{'packet'}->{'icmp'}->{'mtu'} !~ /\d+/) )
	{
	    show_error("Bad MTU " . $config->{'packet'}->{'icmp'}->{'mtu'} . "\n"); 
	    return 1;
	}	
    }
}


# Show Error Message
sub show_error
{
    if($top)
    {
	my $error = $top->Toplevel(-background => 'black');
	$error->title('Error');
	$error->option(add => '*background', 'black');
	$error->option(add => '*foreground', 'red');
	
	$error->Label(-text => $_[0],
		      -border => '0')->pack(-padx => 10, -pady => 10, -side => 'top');
	
	$error->Button(-text => 'OK',
		       -activebackground => 'black',
		       -activeforeground => 'red',
		       -border => 0,
		       -command => sub { $error->destroy })->pack(-pady => 5, -side => 'bottom');
	return 1;
    }
    else
    {
	die "$_[0]\n";
    }
}
