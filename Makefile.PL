use ExtUtils::MakeMaker;

WriteMakefile(
	      NAME => 'P.A.T.H.',
	      EXE_FILES => ['IP-Packet/ip-packet.pl','arpredir/arpredir.pl','crazysniffer/crazysniffer.pl','easterrst/easterrst.pl','feed_snort/feed_snort.pl','hijackd/hijackd.pl','icmpredir/icmpredir.pl'],
	      INSTALLSCRIPT => '/usr/local/bin'
	      );
