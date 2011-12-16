#!/usr/bin/env perl

use strict;                                                                                                               
use warnings;                                                                                                             
use DBI;                                                                                                                  

# prerequisites:
# sudo aptitude install libdbd-sqlite3-perl

# hardcoded filename from sipauthserve.cpp
my $db = DBI->connect("dbi:SQLite:dbname=/etc/OpenBTS/sipauthserve.db","","") or die;

# This script rely on placeholders to prevent SQL-injection attacks
# N. B. above-mentioned statement tells more about my (mis)understanding of SQLi rather than about actual script security

# be verbose?
my $verbose = 1;

if(@ARGV != 2 or @ARGV != 1) { die "Usage example: $0 FileName.cpp [DEBUG]\n"; }

my $key = 'Log.Level.'.$ARGV[0];
my $exist = $db->selectrow_array(qq/select VALUESTRING from CONFIG where "KEYSTRING" == ?/, undef, "$key");

if($exist)
{
    print "$key found: $exist" if $verbose;
    my $plh = $db->prepare("UPDATE CONFIG SET VALUESTRING=? WHERE KEYSTRING==?");
    $plh->execute($ARGV[1], "$key") if $ARGV[1];
}
else
{
    print "$key NOT found" if $verbose;
    my $plh = $db->prepare("INSERT INTO CONFIG (KEYSTRING,VALUESTRING,OPTIONAL) VALUES (?,?,1)");
    $plh->execute($key, $ARGV[1]) if $ARGV[1];
}

if($ARGV[1] and $verbose)
{
    print ", set to ".$db->selectrow_array(qq/select VALUESTRING from CONFIG where "KEYSTRING" == ?/, undef, "$key")."\n";
}
$db->disconnect;
