#!/usr/bin/perl
#
# Perl hijack module test file
#
# Programmed by Bastian Ballmann
# Last update: 05.01.2004
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

use ExtUtils::testlib;
use path::config;

$args{'h'} = '192.168.1.1';
$args{'s'} = '192.168.1.2';
$args{'p'} = 23;

my $cfg = path::config->new();
$cfg->check(%args);
