use ExtUtils::MakeMaker;

#
# Makefile to install the P.A.T.H. modules
#
# Programmed by Bastian Ballmann
# Last update: 04.02.2004
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

BEGIN {

   my @fatal = ();
     
    eval { require Net::ARP };
    if($@)
    {
        print "Module Net::ARP is required!\n";
        print "perl -MCPAN -e 'force install Net::ARP' to install it\n";
	print "If you have problems installing the module please read the FAQ!\n";
	exit(1);
    }
    else
    {
        print "Found Net::ARP\n";
    }
                                                                                          
    eval { require NetPacket::Ethernet };
    if($@)
    {
        print "Module NetPacket::Ethernet is required!\n";
        print "perl -MCPAN -e 'force install NetPacket::Ethernet' to install it\n";
	print "If you have problems installing the module please read the FAQ!\n";
	exit(1);
    }
    else
    {
        print "Found NetPacket::Ethernet\n";
    }


    eval { require NetPacket::IP };
    if($@)
    {
        print "Module NetPacket::IP is required!\n";
        print "perl -MCPAN -e 'force install NetPacket::IP' to install it\n";
	print "If you have problems installing the module please read the FAQ!\n";
	exit(1);
    }
    else
    {
        print "Found NetPacket::IP\n";
    }


    eval { require NetPacket::TCP };
    if($@)
    {
        print "Module NetPacket::TCP is required!\n";
        print "perl -MCPAN -e 'force install NetPacket::TCP' to install it\n";
	print "If you have problems installing the module please read the FAQ!\n";
	exit(1);
    }
    else
    {
        print "Found NetPacket::TCP\n";
    }
                                   

    eval { require Net::RawIP };
    if($@)
    {
        print "Module Net::RawIP is required!\n";
        print "perl -MCPAN -e 'force install Net::RawIP' to install it\n";
	print "If you have problems installing the module please read the FAQ!\n";
	exit(1);
    }
    else
    {
        print "Found Net::RawIP\n";
    }

                                                            
    eval { require Net::Pcap };
    if($@)
    {
        print "Module Net::Pcap is required!\n";
        print "perl -MCPAN -e 'force install Net::Pcap' to install it\n";
	print "If you have problems installing the module please read the FAQ!\n";
	exit(1);
    }
    else
    {
        print "Found Net::Pcap\n";
    }

    eval { require Data::Hexdumper };
    if($@)
    {
        print "Module Data::Hexdumper is required!\n";
        print "perl -MCPAN -e 'force install Data::Hexdumper' to install it\n";
	print "If you have problems installing the module please read the FAQ!\n";
	exit(1);
    }
    else
    {
        print "Found Data::Hexdumper\n";
    }

    eval { require XML::Simple };
    if($@)
    {
        print "Module XML::Simple is required!\n";
        print "perl -MCPAN -e 'force install XML::Simple' to install it\n";
	print "If you have problems installing the module please read the FAQ!\n";
	exit(1);
    }
    else
    {
        print "Found XML::Simple\n";
    }

    eval { require Tk };
    if($@)
    {
        print "Module Tk was NOT found! You are not able to use the gui versions!\n";
    }
    else
    {
        print "Found Tk\n";
    }
}


WriteMakefile(
              NAME => 'modules',
              VERSION => '1.0',
              AUTHOR => 'Bastian Ballmann and Stefan Krecher'
              );
