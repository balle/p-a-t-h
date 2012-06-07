            ______       _______       _______      _______     
           |   __ \     |   _   |     |_     _|    |   |   |    
           |    __/ __  |       | __    |   | __   |       | __ 
           |___|   |__| |___|___||__|   |___||__|  |___|___||__|

            Perl         Advanced        TCP        Hijacking

                    The hijackers P.A.T.H. to galaxy
                    [http://p-a-t-h.sourceforge.net]

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

Icmp Redirector

Programmend by Stefan Krecher
Last Update: 22.12.2002
Licensed under the GPL

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

---:[ Requirements

Perl
Net::RawIP
NetAddr::IP


---:[ Disclaimer

THIS PROJECT WAS DEVELOPED FOR TESTING AND DEMONSTRATION PURPOSE ONLY! 
THE AUTHORS DONT FEEL RESPONSIBLE FOR ILLEGAL ABUSE OF THIS PIECE OF 
SOFTWARE AND WE ADVICE YOU TO USE IT LEGALLY AND DO NOT BREAK THE LAW!

---:[ Description

Icmpredir can be used to change the default gateway (or any other route) 
of a victims host. It's used to implement man-in-the-middle attacks.
The OS / kernel of the victims host must be able to accept icmp-redirects
and the attack is only possible if the target host isn't a "router" or
checks /proc/sys/net/ipv4/conf/all/accept_redirects


---:[ Installation

If your system supports Perl just install the required modules. 
Be sure that you have also installed the libpcap library.
You get it here [http://www.tcpdump.org]


---:[ Usage

Run ./icmpredir.pl --help to get help

:[EOF