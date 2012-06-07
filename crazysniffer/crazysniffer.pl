#!/usr/bin/perl
# Yet another network and password sniffer
#
# Written by Bastian Ballmann [ Crazydj@chaostal.de ]
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


# Are you root?
die "You must be root...\n\n" if($> != 0);


###[ Loading modules ]###

use Net::Pcap;                      # Sniffin around
use NetPacket::Ethernet qw(:strip); # Decoding Ethernet packets
use NetPacket::IP qw(:strip);       # Decoding IP packets
use NetPacket::TCP;                 # Decoding TCP packets
use Data::Hexdumper;                # Dump Hex
use Getopt::Std;                    # Parsing parameter
use path::config;                   # P.A.T.H. configuration
use path::hijack;                   # P.A.T.H. hijacking stuff
use IO::Select;                     # Watching pipes
use strict;                         # Be strict!

# Do you have X and Tk?
BEGIN 
{
    eval{ require Tk; };              
    import Tk unless $@;

    eval{ require Tk::FileSelect; };  
    import Tk::FileSelect unless $@;
};


###[ Global variables ]###

my ($snaplen,%sequence,$username,$password);
my $flag = 0;

# Remember the dumped packets
my %ips;

# Watch child pipes
my $watcher = new IO::Select;

# Pipes and pid of the child process
my ($read,$write,$pid);

# Create config object
my $cfg = path::config->new();

# Parameter hash
my %args;

# Pcap filter expression
my $filter = "";

# Write output to a file?
my $output;

# Global Tk objects
my ($top, $result, $device_entry, $number_entry, $pcap_expr_entry, $quick_pcap, $grep_expr_entry, $quick_grep, $snap_entry, $print_seq, $print_flags, $print_winsize, $hex, $sniffin_mode, $cfg_win, $mode_win);


###[ MAIN PART ]###

# Autoflush Output
$|=1;

# Need help?
usage() if($ARGV[0] eq "--help");

# Load GUI version?
if($ARGV[0] eq "--gui")
{
    draw_gui();
}
else
{
    # Read in parameter
    getopts('w:l:i:f:e:n:aFPSmqtWXx', \%args);
    start();
}


###[ Subroutines ]###

sub start
{
    # Check parameter
    exit(1) if($cfg->check(%args) == 1);

    # Has the user chosen more than one sniffin mode?
    my $count_mode = 0;
    $count_mode++ if($args{t});
    $count_mode++ if($args{m});
    $count_mode++ if($args{X});

    if($count_mode > 1)
    {
	print_error("Please choose either -m, -t or -X\n\n");
    }

    # Telnet sniffin mode
    if($args{'t'})
    {
	if($ARGV[0] eq "--gui")
	{
	    $result->insert('end',"Telnet sniffin mode\n\n");
	    $result->see('end');
	    $top->update();
	}
	else
	{
	    print "Telnet sniffin mode\n\n";
	}

	$filter = "tcp and port 23";
    }

    # Mail sniffin mode
    elsif($args{'m'})
    {
	if($ARGV[0] eq "--gui")
	{
	    $result->insert('end',"Mail sniffin mode\n\n");
	    $result->see('end'),
	    $top->update;
	}
	else
	{
	    print "Mail sniffin mode\n\n";
	}

	$filter = "tcp and port 25 or port 110 or port 143";
    }

    # Password sniffin mode
    elsif($args{'X'})
    {
	if($ARGV[0] eq "--gui")
	{
	    $result->insert('end',"Password sniffin mode\n\n");
	    $result->see('end');
	    $top->update;
	}
	else
	{
	    print "Password sniffin mode\n\n";
	}

	$filter = "tcp and port 21 or port 23 or port 25 or port 110 or port 143";	
    }

    # User defined Pcap expression
    if($args{'f'})
    {
	if($filter eq "")
	{
	    $filter = $args{'f'};
	}
	else
	{
	    $filter .= " and $args{'f'}";
	}
    }

    # Dump payload to a file?
    if($args{'w'})
    {
	$output = $args{'w'};

	if($ARGV[0] eq "--gui")
	{
	    $result->insert('end',"Savin output to file $output\n");
	    $result->see('end');
	    $top->update;
	}
	else
	{
	    print "Saving output to file $output\n";
	}

	open(O,">$output") || print_error("Cannot write to $output!\n$!\n");
    }
    
    # Number of bytes to capture from each packet
    $snaplen = $args{'l'};

    # Default snaplen    
    $snaplen = 2048 if($snaplen eq "");

    if($ARGV[0] eq "--gui")
    {
	$result->insert('end',"Start sniffin $filter on device " . $cfg->get_device . "...\n");
	$result->insert('end',"Searching for $args{'e'}\n") if $args{'e'} ne "";
	$result->see('end');
	$top->update();
    }
    else
    {
	print "Start sniffin $filter on device " . $cfg->get_device . "...\n" unless $args{'q'};
	print "Searching for $args{'e'}\n" unless( $args{'e'} eq "" || $args{'q'} );
    }

    # Create a child process
    ($read,$write,$pid) = mkchild();

    # Add the read pipe to the watcher list
    $watcher->add($read);

    # Start sniffin
    if($args{'n'})
    {
	print "Sniffin only $args{'n'} packets\n" unless( $top || $args{'q'} ) ;
	my $count = 0;

	while($count < $args{'n'})
	{
	    $top->update if $ARGV[0] eq "--gui";

	    # The child process has got something for us
	    if($watcher->can_read(1))
	    {
		my $msg = pipe_read($read);
		
		# Oh damn! There was an error!
		if($msg =~ /^\[err\]\s/)
		{
		    print_error($');
		    sleep 1;
		    pipe_write($write,"KILL");
		    $watcher->remove($read);
		    return 1;
		}
		
		# Hehe. The kid has caught a packet
		else
		{
		    sniffit($msg);
		    $count++;
		}
	    }
	}

	exit(0);
    }
    else
    {
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
		    print_error($');
		    sleep 1;
		    pipe_write($write,"KILL");
		    $watcher->remove($read);
		    return 1;
		}
		
		# Hehe. The kid has caught a packet
		else
		{
		    sniffit($msg);
		}
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
	my $pcap_dev = Net::Pcap::open_live($cfg->get_device, $snaplen, 1, 1500, \$errbuf);

	if(defined $pcap_dev)
	{
	    # Compile and set the filter
	    my ($net, $mask, $cfilter);
	    Net::Pcap::lookupnet($cfg->get_device, \$net, \$mask, \$errbuf);
	    Net::Pcap::compile($pcap_dev,\$cfilter,$filter,0,$mask);
	    Net::Pcap::setfilter($pcap_dev,$cfilter);

	    # Start sniffin
	    while(1)
	    {
		if($child_watcher->can_read(0.1))
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
	    print "CHILD $$ there was an error\n";
	    pipe_write($child_write,"[err] Error while opening device ".$cfg->get_device."!\n$errbuf");
	    
	    # Wait until the father forces us to suicide
	    print "WAITING...\n";
	    while(1)
	    {
		if($child_watcher->can_read())
		{
		    my $msg = pipe_read($father_read);
		    exit(0) if $msg eq "KILL";
		}
	    }
	}
    }
}


# Write data into a pipe
# Parameter: Pipe, Message
sub pipe_write
{
    my ($pipe,$msg) = @_;
    return unless defined $pipe;
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


# Decode packets and payload
# Parse the payload
sub sniffit
{
    my $packet = shift;

    # Decode packet header and data
    my $ip = NetPacket::IP->decode(eth_strip($packet));
    my $tcp = NetPacket::TCP->decode($ip->{data});
    my $dump = $tcp->{data};

    # Redraw GUI
    $top->update if $ARGV[0] eq "--gui";

    # Telnet sniffin mode
    if($args{'t'})
    {
	# Wurde die IP / Port schon ausgegeben?
	unless($ips{"$ip->{src_ip}:$tcp->{src_port} $ip->{dest_ip}:$tcp->{dest_port}"})
	{
	    $ips{"$ip->{src_ip}:$tcp->{src_port} $ip->{dest_ip}:$tcp->{dest_port}"} = 1;

	    if($ARGV[0] eq "--gui")
	    {
		$result->insert('end',"$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port}\n\n");
		$result->see('end');
		$top->update();
	    }
	    else
	    {
		print "$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port}\n\n";
	    }

	    # Dump this to a file?
	    print O "$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port}\n\n" if($args{'w'});
	}

	# Was this packet dumped before?
	unless($sequence{$tcp->{seqnum}})
	{
	    $sequence{$tcp->{seqnum}} = 1;
	    $dump =~ s/\r\n/\n/g;
	    $dump =~ s/\^M/\n/g;

	    if($ARGV[0] eq "--gui")
	    {
		$result->insert('end',"$dump");
		$result->see('end');
		$top->update();
	    }
	    else
	    {
		print $dump;	
	    }

	    # Dump this to a file?
	    print O "$dump" if($args{'w'});
	}
    }

    # Mail sniffin mode
    elsif($args{'m'})
    {
	# Was this packet dumped before?
	unless($ips{"$ip->{src_ip}:$tcp->{src_port} $ip->{dest_ip}:$tcp->{dest_port}"})
	{
	    $ips{"$ip->{src_ip}:$tcp->{src_port} $ip->{dest_ip}:$tcp->{dest_port}"} = 1;
	    
	    if($ARGV[0] eq "--gui")
	    {
		$result->insert('end',"$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port}\n\n");
		$result->see('end');
		$top->update();
	    }
	    else
	    {
		print "$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port}\n\n";
	    }
	    
	    # Dump this to a file?
	    print O "$ip->{src_ip}:$tcp->{src_port} --> $ip->{dest_ip}:$tcp->{dest_port}\n\n" if($args{'w'});
	}

	if($ARGV[0] eq "--gui")
	{
	    $result->insert('end',"$dump");
	    $result->see('end');
	    $top->update();
	}
	else
	{
	    print $dump;
	}

	# Dump this to file?
	print O "$dump" if($args{'w'});

	if($dump =~ /QUIT/i)
	{
	    if($ARGV[0] eq "--gui")
	    {
		$result->insert('end',"-=" x 40 . "\n");
		$result->see('end');
		$top->update();
	    }
	    else
	    {
		print "-=" x 40 . "\n";
	    }
	
	    # Dump this to a file?
	    print O "-=" x 40 . "\n" if($args{'w'});
	}
    }

    # Password snffin mode
    elsif($args{'X'})
    {
	# FTP / POP Login
	if( ($dump =~ /PASS/) || ($dump =~ /USER/) )
	{
	    print_dump($packet);
	}

	# IMAP Login
	elsif( ($dump =~ /login/i) && ($tcp->{'dest_port'} == 143) )
	{
	    print_dump($packet);
	}
	else
	{
	    # Telnet Login
	    if($dump =~ /Last/)
	    {
		$flag = 3;
	    }
	    elsif($dump =~ /login/)
	    {
		$flag = 1;
		return;
	    }
	    elsif($dump =~ /Password/)
	    {
		$flag = 2;
		return;
	    }

	    # Save Username
	    if($flag == 1)
	    {
		return if($sequence{$tcp->{seqnum}});
	    }
	    else
	    {
		$sequence{$tcp->{seqnum}} = 1;
	    }

	    chomp $dump;
	    $username .= $dump;
	}

	# Save password
	if($flag == 2)
	{
	    chomp $dump;
	    $password .= $dump;
	}

	if($flag == 3)
	{
	    $dump = "Username $username\nPassword $password\n\n";
	    print_dump($packet,$dump);
	    $flag = 0;
	    $username = "";
	    $password = "";
	}
    }

    # Normal sniffin mode
    else
    {
	print_dump($packet);
    }
}


# Print out packet header information
sub print_dump
{
    my($packet,$dump) = @_;
    my $ip = NetPacket::IP->decode(eth_strip($packet));
    my $tcp = NetPacket::TCP->decode($ip->{data});
    my $flags = "";
    
    $dump = $tcp->{data} if($dump eq "");
    my $output = "$ip->{src_ip}:$tcp->{src_port}  -->  $ip->{dest_ip}:$tcp->{dest_port}";

    # Print Sequence and Acknowledgement numbers?
    $output .= " Seq: " . $tcp->{seqnum} . " Ack: " . $tcp->{acknum} if( (($args{'S'}) || ($args{'a'})) );

    # Print TCP Flags?
    if( ($args{'F'}) || ($args{'a'}) )
    {
	$flags .= "SYN " if(path::hijack::check_flag('',$packet,"syn"));
	$flags .= "ACK " if(path::hijack::check_flag('',$packet,"ack"));
	$flags .= "RST " if(path::hijack::check_flag('',$packet,"rst"));
	$flags .= "FIN " if(path::hijack::check_flag('',$packet,"fin"));
	$flags .= "PSH " if(path::hijack::check_flag('',$packet,"psh"));
	$flags .= "URG " if(path::hijack::check_flag('',$packet,"urg"));
	$output .= " Flags: $flags";
    }

    # Print Window size?
    $output .= " Win: " . $tcp->{winsize} if( ($args{'W'}) || ($args{'a'}) );
    chomp $dump;

    # Grep payload?
    return if ( ($args{'e'} ne "") && ($dump !~ /$args{'e'}/ig) );

    # Print Payload in Hex?
    $dump = Data::Hexdumper::hexdump( data => $dump, format => "H" ) if( ($args{'x'}) && ($dump ne "") );

    # Write the output to a file?
    if($args{'w'})
    {
	print O "$output\n";
	print O "$dump\n\n" unless ( ($dump eq "") || ($dump =~ /^\s+$/) || ($args{'q'}) );
    }

    # GUI
    if($ARGV[0] eq "--gui")
    {
	$result->insert('end',"$output\n");
	$result->insert('end',"$dump\n\n") unless ( ($dump eq "") || ($dump =~ /^\s+$/) || ($args{'q'}) );
	$result->see('end');
	$top->update();
    }
    
    # Terminal
    else
    {
	print "$output\n" unless defined $args{'P'};

	if($args{'P'})
	{
	    # Wurde die IP / Port schon ausgegeben?
	    unless($ips{"$ip->{src_ip}:$tcp->{src_port} $ip->{dest_ip}:$tcp->{dest_port}"})
	    {
		$dump =~ s/[^\w^\d^\s]//g;
		print "$dump\n" unless ( ($dump eq "") || ($dump =~ /^\s+$/) );
	    }
	}
	else
	{
	    print "$dump\n\n" unless ( ($dump eq "") || ($dump =~ /^\s+$/) || ($args{'q'}) );
	}
    }
}


# Close filehandle if some output was written to a file
# or if the program was interrupted.
sub save_file
{
    close(O) if($args{'w'});
    pipe_write($write,"KILL");
    waitpid($pid,'-1');
    exit(0);
}

# Print an error message
sub print_error { ($ARGV[0] eq "--gui") ? show_error($_[0]) : die "$_[0]"; }

# Print usage
sub usage
{
    print "\nCrazysniffer - Yet another password and network sniffer\n";
    print "-------------------------------------------------------\n";
    print "Programmed by Bastian Ballmann [ Crazydj\@chaostal.de ]\n\n";
    print "Usage $0 -aefFilmnPqStwxX\n\n";
    print "[-a dump all headers options]\n";
    print "[-e string-to-grep]\n";
    print "[-f pcap-expression]\n";
    print "[-F print TCP flags]\n";
    print "[-i interface]\n"; 
    print "[-l snaplen] \n";
    print "[-m mail sniffin]\n";
    print "[-n number-of-packets]\n";
    print "[-P print only payload]\n";
    print "[-q dont dump payload]\n";
    print "[-S print Sequence and Acknowledgement numbers]\n";
    print "[-t telnet sniffin]\n";
    print "[-w save-to-file]\n";
    print "[-W print window-size]\n";
    print "[-x dump hex]\n";
    print "[-X password sniffin]\n";
    print "--gui to start the gui version\n\n";
    exit(0);
}


###[ The GUI code ]###

sub draw_gui
{
    # Main window
    $top = MainWindow->new(-background => 'black', -foreground => 'green');
    $top->title('[ Crazy Sniffer ]');
    $top->option(add => '*background', 'black');
    $top->option(add => '*foreground', 'green');

    # Frames
    my $content = $top->Frame->pack(-side => 'top', -pady => 5, -padx => 10);
    my $toolbar = $top->Frame->pack(-side => 'bottom', -pady => 5, -padx => 10);
    my $pcap_frame = $top->Frame->pack(-side => 'bottom', -pady => 5, -padx => 10);
    my $grep_frame = $top->Frame->pack(-side => 'bottom', -pady => 5, -padx => 10);
    my $number_frame = $top->Frame->pack(-side => 'bottom', -pady => 5, -padx => 10);
    my $result_frame = $top->Frame->pack(-side => 'bottom', -pady => 10, -padx => 10);

    # Menubar
    my $menu = $top->Menu(-type => 'menubar');
    $menu->configure(-border => 3);
    my $conf = $menu->cascade('-label' => 'Configure', '-tearoff' => 0);
    $conf->configure(-activebackground => 'black',
		     -activeforeground => 'red');

    $conf->command('-label' => 'General stuff',
		   -activebackground => 'black',
		   -activeforeground => 'red',
		   -command => \&general_config);

    $conf->command('-label' => 'Select Sniffin Mode',
		   -activebackground => 'black',
		   -activeforeground => 'red',
		   -command => \&sniffin_mode);

    $conf->command('-label' => 'Save Config',
		   -activebackground => 'black',
		   -activeforeground => 'red',
		   -command => \&save_config);

    $conf->command('-label' => 'Load Config',
		   -activebackground => 'black',
		   -activeforeground => 'red',
		   -command => \&load_config);

    $conf->command('-label' => 'Save Traffic',
		   -activebackground => 'black',
		   -activeforeground => 'red',
		   -command => \&save_traffic);

    my $about = $menu->cascade('-label' => 'About', '-tearoff' => 0);
    $about->configure(-activebackground => 'black',
		      -activeforeground => 'red');

    $about->command('-label' => 'About this tool',
		    -activebackground => 'black',
		    -activeforeground => 'red',
		    -command => \&about);

    $top->configure(-menu => $menu, -border => 3);
    

    # Labels
    $content->Label(-text => '[ Crazysniffer -- Programmed by Bastian Ballmann ]',
		    -border => 0)->pack(-pady => 5);

    $content->Label(-text => '-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-',
		    -border => 0)->pack();

    # String to grep in payload
    $grep_frame->Label(-text => 'Grep Expression:',
		       -border => 0)->pack(-pady => 10, -side => 'left', -padx => 5);
    
    $quick_grep = $grep_frame->Entry(-background => '#3C3C3C',
				     -width => 30)->pack(-pady => 10, -padx => 5, -side => 'left');

    # Set Pcap Expression
    $pcap_frame->Label(-text => 'Pcap Expression:',
		       -border => 0)->pack(-pady => 10, -side => 'left', -padx => 5);
    
    $quick_pcap = $pcap_frame->Entry(-background => '#3C3C3C',
				     -width => 30)->pack(-pady => 10, -padx => 5, -side => 'left');

    # Toolbar
    $toolbar->Button(-text => 'Start sniffin',
		     -activebackground => 'black',
		     -activeforeground => 'red',
		     -borderwidth => 0,
		     -border => 0,
		     -command => \&start_sniffer)->pack(-side => 'left', -padx => 10);

    $toolbar->Button(-text => 'Quit',
		     -activebackground => 'black',
		     -activeforeground => 'red',
		     -borderwidth => 0,
		     -border => 0,
		     -command => sub { exit(0); })->pack(-side => 'right', -padx => 10);

    # Output
    $result_frame->Label(-text => 'Output',
			 -border => 0)->pack(-side => 'top', -pady => 5);

    $result = $result_frame->Scrolled('Text',
				      -border => 4,
				      -width => 100,
				      -height => 20)->pack(-side => 'bottom', -pady => 5);
    $result->configure(-scrollbars => 'e');

    MainLoop();
}


# Window to configure general stuff
sub general_config
{
    # New Window
    $cfg_win = $top->Toplevel;
    $cfg_win->title('General Configuration');
    $cfg_win->option(add => '*background', 'black');
    $cfg_win->option(add => '*foreground', 'green');
    
    # Define Frames
    my $cfg_label = $cfg_win->Frame();
    my $cfg_dev = $cfg_win->Frame();
    my $cfg_pcap = $cfg_win->Frame();
    my $cfg_grep = $cfg_win->Frame();
    my $cfg_number = $cfg_win->Frame();
    my $cfg_snap = $cfg_win->Frame();
    my $cfg_seq = $cfg_win->Frame();
    my $cfg_flags = $cfg_win->Frame();
    my $cfg_winsize = $cfg_win->Frame();
    my $cfg_hex = $cfg_win->Frame();
    my $cfg_unten = $cfg_win->Frame();

    # Content
    $cfg_label->Label(-text => 'General Configuration',
		      -border => 0)->pack(-pady => 5);

    $cfg_label->Label(-text => '-=-=-=-=-=-=-=-=-=-=-=-=-=-=-',
		      -border => 0)->pack();


    $cfg_dev->Label(-text => 'Network device:',
		    -border => 0)->pack(-side => 'left', -pady => 5, -padx => 5, -anchor => 'w');

    $device_entry = $cfg_dev->Entry(-background => '#3C3C3C')->pack(-side => 'right', -pady => 5, -padx => 5, -anchor => 'e');

    if($args{'i'} eq "")
    {
	my $errbuf;
	$device_entry->insert(0,Net::Pcap::lookupdev(\$errbuf));
    }
    else
    {
	$device_entry->insert(0,$args{'i'});
    }
                                 
    $cfg_number->Label(-text => 'Number of packets:',
		     -border => 0)->pack(-side => 'left', -pady => 5, -padx => 5, -anchor => 'w');

    $number_entry = $cfg_number->Entry(-background => '#3C3C3C')->pack(-side => 'right', -pady => 5, -padx => 5, -anchor => 'e');

    $number_entry->insert(0,$args{'n'}) unless($args{'n'} eq "");

    $cfg_grep->Label(-text => 'Grep expression:',
		     -border => 0)->pack(-side => 'left', -pady => 5, -padx => 5, -anchor => 'w');

    $grep_expr_entry = $cfg_grep->Entry(-background => '#3C3C3C')->pack(-side => 'right', -pady => 5, -padx => 5, -anchor => 'e');

    $grep_expr_entry->insert(0,$args{'e'}) unless($args{'e'} eq "");

    $cfg_pcap->Label(-text => 'Pcap expression:',
		     -border => 0)->pack(-side => 'left', -pady => 5, -padx => 5, -anchor => 'w');

    $pcap_expr_entry = $cfg_pcap->Entry(-background => '#3C3C3C')->pack(-side => 'right', -pady => 5, -padx => 5, -anchor => 'e');

    $pcap_expr_entry->insert(0,$args{'f'}) unless($args{'f'} eq "");

    $cfg_snap->Label(-text => 'Snaplen:',
		     -border => 0)->pack(-side => 'left', -pady => 5, -padx => 5, -anchor => 'w');

    $snap_entry = $cfg_snap->Entry(-background => '#3C3C3C')->pack(-side => 'right', -pady => 5, -padx => 5, -anchor => 'e');

    if($args{'l'} eq "")
    {
	$snap_entry->insert(0,"2048");
    }
    else
    {
	$snap_entry->insert(0,$args{'l'});
    }

    if($args{'S'} eq "")
    {
	$print_seq = 0;
    }
    else
    {
	$print_seq = $args{'S'};
    }

    $cfg_seq->Label(-text => 'Dump Sequence Numbers:',
		    -border => 0)->pack(-side =>'left', -pady => 5, -padx => 5);

    $cfg_seq->Radiobutton(-variable => \$print_seq,
			  -value => 1,
			  -text => 'Yes',
			  -activebackground => 'black',
			  -activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);

    $cfg_seq->Radiobutton(-variable => \$print_seq,
			  -value => 0,
			  -text => 'No',
			  -activebackground => 'black',
			  -activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);

    if($args{'F'} eq "")
    {
	$print_flags = 0;
    }
    else
    {
	$print_flags = $args{'F'};
    }

    $cfg_flags->Label(-text => 'Dump TCP Flags:',
		      -border => 0)->pack(-side =>'left', -pady => 5, -padx => 5);

    $cfg_flags->Radiobutton(-variable => \$print_flags,
			    -value => 1,
			    -text => 'Yes',
			    -activebackground => 'black',
			    -activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);

    $cfg_flags->Radiobutton(-variable => \$print_flags,
			    -value => 0,
			    -text => 'No',
			    -activebackground => 'black',
			    -activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);

    if($args{'W'} eq "")
    {
	$print_winsize = 0;
    }
    else
    {
	$print_winsize = $args{'W'};
    }

    $cfg_winsize->Label(-text => 'Dump window size:',
			-border => 0)->pack(-side =>'left', -pady => 5, -padx => 5);

    $cfg_winsize->Radiobutton(-variable => \$print_winsize,
			      -value => 1,
			      -text => 'Yes',
			      -activebackground => 'black',
			      -activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);

    $cfg_winsize->Radiobutton(-variable => \$print_winsize,
			      -value => 0,
			      -text => 'No',
			      -activebackground => 'black',
			      -activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);


    if($args{'x'} eq "")
    {
	$hex = 0;
    }
    else
    {
	$hex = $args{'x'};
    }
    
    $cfg_hex->Label(-text => 'Dump payload in hex:',
		    -border => 0)->pack(-side => 'left', -pady => 5, -padx => 5);

    $cfg_hex->Radiobutton(-variable => \$hex,
			  -value => 1,
			  -text => 'Yes',
			  -activebackground => 'black',
			  -activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);

    $cfg_hex->Radiobutton(-variable => \$hex,
			  -value => 0,
			  -text => 'No',
			  -activebackground => 'black',
			  -activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);

    $cfg_unten->Button(-text => 'OK',
		       -activebackground => 'black',
		       -activeforeground => 'red',
		       -border => 0,
		       -command => \&save_general_config)->pack(-side => 'left', -pady => 10, -padx => 10);

    $cfg_unten->Button(-text => 'Close',
		       -activebackground => 'black',
		       -activeforeground => 'red',
		       -border => 0,
		       -command => sub { $cfg_win->destroy })->pack(-side => 'left', -pady => 10, -padx => 10);

    $cfg_label->pack(-anchor => 'n', -padx => 10, -pady => 10);
    $cfg_dev->pack(-anchor => 'e', -padx => 10);
    $cfg_number->pack(-anchor => 'e', -padx => 10);
    $cfg_grep->pack(-anchor => 'e', -padx => 10);
    $cfg_pcap->pack(-anchor => 'e', -padx => 10);
    $cfg_snap->pack(-anchor => 'e', -padx => 10);
    $cfg_seq->pack(-anchor => 'e', -padx => 10);
    $cfg_flags->pack(-anchor => 'e', -padx => 10);
    $cfg_winsize->pack(-anchor => 'e', -padx => 10);
    $cfg_hex->pack(-anchor => 'e', -padx => 10);
    $cfg_unten->pack(-anchor => 's', -padx => 10);
}


# Open Window to configure Sniffin Mode
sub sniffin_mode
{
    # New Window
    $mode_win = $top->Toplevel;
    $mode_win->title('Configure Sniffin Mode');
    $mode_win->option(add => '*background', 'black');
    $mode_win->option(add => '*foreground', 'green');

    # Define Frames
    my $mode_top = $mode_win->Frame();
    my $mode_normal = $mode_win->Frame();
    my $mode_pass = $mode_win->Frame();
    my $mode_telnet = $mode_win->Frame();
    my $mode_mail = $mode_win->Frame();
    my $mode_bottom = $mode_win->Frame();

    # Content
    $sniffin_mode = "";

    $mode_top->Label(-text => 'Configure Sniffin Mode',
		     -border => 0)->pack(-pady => 5, -padx => 10);

    $mode_top->Label(-text => '-=-=-=-=-=-=-=-=-=-=-=-',
		     -border => 0)->pack();

    $mode_normal->Label(-text => 'Normal sniffin:',
			-border => 0)->pack(-pady => 5, -padx => 5, -side => 'left');
			
    my $default_mode = $mode_normal->Checkbutton(-variable => \$sniffin_mode,
						 -offvalue => 'normal',
						 -onvalue => 'normal',
						 -activebackground => 'black',
						 -activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);

    $mode_pass->Label(-text => 'Password sniffin:',
		      -border => 0)->pack(-pady => 5, -padx => 5, -side => 'left');

    my $password_mode = $mode_pass->Checkbutton(-variable => \$sniffin_mode,
						-offvalue => 'normal',
						-onvalue => 'password',
						-activebackground => 'black',
						-activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);
    
    $mode_telnet->Label(-text => 'Telnet sniffin:',
			-border => 0)->pack(-pady => 5, -padx => 5, -side => 'left');

    my $telnet_mode = $mode_telnet->Checkbutton(-variable => \$sniffin_mode,
						-offvalue => 'normal',
						-onvalue => 'telnet',
						-activebackground => 'black',
						-activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);

    $mode_mail->Label(-text => 'Mail sniffin:',
		      -border => 0)->pack(-pady => 5, -padx => 5, -side => 'left');
    
    my $mail_mode = $mode_mail->Checkbutton(-variable => \$sniffin_mode,
					    -offvalue => 'normal',
					    -onvalue => 'mail',
					    -activebackground => 'black',
					    -activeforeground => 'red')->pack(-side => 'left', -pady => 5, -padx => 5);

    if($args{'X'} == 1)
    {
	$password_mode->select();
    }
    elsif($args{'t'} == 1)
    {
	$telnet_mode->select();
    }
    elsif($args{'m'} == 1)
    {
	$mail_mode->select();
    }
    else
    {
	$default_mode->select();
    }

    $mode_bottom->Button(-text => 'OK',
			 -activebackground => 'black',
			 -activeforeground => 'red',
			 -border => 0,
			 -command => \&save_mode_config)->pack(-side => 'left', -pady => 10, -padx => 10);

    $mode_bottom->Button(-text => 'Close',
			 -activebackground => 'black',
			 -activeforeground => 'red',
			 -border => 0,
			 -command => sub { $mode_win->destroy })->pack(-side => 'left', -pady => 10, -padx => 10);

    $mode_top->pack(-anchor => 'n', -padx => 10, -pady => 10, -side => 'top');
    $mode_normal->pack(-anchor => 'e', -padx => 10, -side => 'top');
    $mode_pass->pack(-anchor => 'e', -padx => 10, -side => 'top');
    $mode_telnet->pack(-anchor => 'e', -padx => 10, -side => 'top');
    $mode_mail->pack(-anchor => 'e', -padx => 10, -side => 'top');
    $mode_bottom->pack(-anchor => 's', -padx => 10, -side => 'bottom');
}


# Reading general config
sub save_general_config
{
    my $tmp;

    $tmp = $device_entry->get;
    $args{'i'} = $tmp;
    $tmp = $pcap_expr_entry->get;
    $args{'f'} = $tmp;
    $tmp = $grep_expr_entry->get;
    $args{'e'} = $tmp;
    $tmp = $number_entry->get;
    $args{'n'} = $tmp;
    $tmp = $snap_entry->get;
    $args{'l'} = $tmp;
 
    # What to dump?
    $args{'S'} = $print_seq if($print_seq);
    $args{'F'} = $print_flags if($print_flags);
    $args{'W'} = $print_winsize if($print_winsize);
    $args{'x'} = $hex if($hex);
    $cfg_win->destroy;
}


# Read sniffin mode config
sub save_mode_config
{
    if($sniffin_mode eq "password")
    {
	$args{'X'} = 1	
    }
    elsif($sniffin_mode eq "telnet")
    {
	$args{'t'} = 1;
    }
    elsif($sniffin_mode eq "mail")
    {
	$args{'m'} = 1;
    }
    
    $mode_win->destroy;
}

# Save configuration
sub save_config
{
    my $f = $top->FileSelect(-directory => ".",
			     -filter => "*");

    my $cfgfile = $f->Show();
    return if $cfgfile eq "";

    my $config = {};
    $config->{'parameter'}->{'device'} = $args{'i'};
    $config->{'parameter'}->{'pcap'} = $args{'f'};
    $config->{'parameter'}->{'grep'} = $args{'e'};
    $config->{'parameter'}->{'number'} = $args{'n'};
    $config->{'parameter'}->{'snaplen'} = $args{'l'};
    $config->{'parameter'}->{'crazysniffer'}->{'print'}->{'seq'} = $args{'S'};
    $config->{'parameter'}->{'crazysniffer'}->{'print'}->{'flags'} = $args{'F'};
    $config->{'parameter'}->{'crazysniffer'}->{'print'}->{'winsize'} = $args{'W'};
    $config->{'parameter'}->{'crazysniffer'}->{'print'}->{'hex'} = $args{'x'};	
    $config->{'parameter'}->{'crazysniffer'}->{'mode'}->{'password'} = $args{'X'};
    $config->{'parameter'}->{'crazysniffer'}->{'mode'}->{'telnet'} = $args{'t'};
    $config->{'parameter'}->{'crazysniffer'}->{'mode'}->{'mail'} = $args{'m'};
	
    path::config::writecfg($config,$cfgfile);
}


# Load configuration
sub load_config
{
    my $f = $top->FileSelect(-directory => ".",
			     -filter => "*");
    
    my $file = $f->Show();
    
    unless($file eq "")
    {
	# Gibt es die Datei?
	unless(-f $file)
	{
	    show_error("Cannot find file $file!\n");
	    return;
	}

	my $config = path::config::readcfg($file);
	
	$args{'i'} = $config->{'parameter'}->{'device'};
	$args{'n'} = $config->{'parameter'}->{'number'};
	$args{'e'} = $config->{'parameter'}->{'grep'};
	$args{'f'} = $config->{'parameter'}->{'pcap'};
	$args{'l'} = $config->{'parameter'}->{'snaplen'};

	if($config->{'parameter'}->{'crazysniffer'}->{'print'}->{'seq'} == 1)
	{
	    $args{'S'} = $config->{'parameter'}->{'crazysniffer'}->{'print'}->{'seq'};
	}

	if($config->{'parameter'}->{'crazysniffer'}->{'print'}->{'flags'} == 1)
	{
	    $args{'F'} = $config->{'parameter'}->{'crazysniffer'}->{'print'}->{'flags'};
	}

	if($config->{'parameter'}->{'crazysniffer'}->{'print'}->{'winsize'} == 1)
	{
	    $args{'W'} = $config->{'parameter'}->{'crazysniffer'}->{'print'}->{'winsize'};
	}

	if($config->{'parameter'}->{'crazysniffer'}->{'print'}->{'hex'} == 1)
	{
	    $args{'x'} = $config->{'parameter'}->{'crazysniffer'}->{'print'}->{'hex'};
	}
	
	if($config->{'parameter'}->{'crazysniffer'}->{'mode'}->{'password'} == 1)
	{
	    $args{'X'} = $config->{'parameter'}->{'crazysniffer'}->{'mode'}->{'password'};
	}
	
	if($config->{'parameter'}->{'crazysniffer'}->{'mode'}->{'telnet'} == 1)
	{
	    $args{'t'} = $config->{'parameter'}->{'crazysniffer'}->{'mode'}->{'telnet'};
	}
	
	if($config->{'parameter'}->{'crazysniffer'}->{'mode'}->{'mail'} == 1)
	{
	    $args{'m'} = $config->{'parameter'}->{'crazysniffer'}->{'mode'}->{'mail'};
	}
    }
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


# Save traffic
sub save_traffic
{
    my $tmp;
    my $f = $top->FileSelect(-directory => ".",
			     -filter => "*");

    $tmp = $f->Show();
    $args{'w'} = $tmp unless($tmp eq "");
}

# Start the sniffer
sub start_sniffer
{
    my $tmp = $quick_pcap->get();
    $args{'f'} = $tmp unless($tmp eq "");
    my $tmp = $quick_grep->get();
    $args{'e'} = $tmp unless($tmp eq "");
    start(%args);
}


# Print about
sub about
{
    my $aboutwin = $top->Toplevel;
    $aboutwin->title('About this nice tool');
    $aboutwin->option(add => '*background', 'black');
    $aboutwin->option(add => '*foreground', 'green');

    $aboutwin->Label(-text => 'Crazysniffer - Yet another password and network sniffer',
		     -border => 0)->pack(-pady => 10, -padx => 10);

    $aboutwin->Label(-text => 'Programmed by Bastian Ballmann',
		     -border => 0)->pack(-padx => 10);

    $aboutwin->Label(-text => 'Last Update 24.07.2004',
		     -border => 0)->pack(-pady => 5);

    my $downtown = $aboutwin->Frame()->pack(-pady => 20);

    $downtown->Button(-text => 'Just close it!',
		      -activebackground => 'black',
		      -activeforeground => 'red',
		      -borderwidth => 5,
		      -command => sub { destroy $aboutwin})->pack();
}

