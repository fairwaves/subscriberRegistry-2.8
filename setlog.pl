#!/usr/bin/env perl

use strict;                                                                                                               
use warnings;                                                                                                             
use DBI;                                                                                                                  

# prerequisites:
# sudo aptitude install libdbd-sqlite3-perl                                                                               

# hardcoded filename from sipauthserve.cpp
my $db = DBI->connect("dbi:SQLite:dbname=/etc/OpenBTS/sipauthserve.db","","") or die;                                            

# be verbose?
my $verbose = 1;

if(@ARGV != 2) { print "Usage example: $0 FileName.cpp DEBUG\n"; exit 1; }

my $key = 'Log.Level.'.$ARGV[0];
my $exist = $db->selectrow_array(qq/select VALUESTRING from CONFIG where "KEYSTRING" == "$key"/);                         

if($exist)
{
    print "$key found: $exist" if $verbose;
    $db->do("UPDATE CONFIG SET VALUESTRING=\"".$ARGV[1]."\" WHERE KEYSTRING==\"".$key."\"");
}
else
{
    print "$key NOT found" if $verbose;
    $db->do("INSERT INTO CONFIG (KEYSTRING,VALUESTRING,OPTIONAL) VALUES (\"".$key."\",\"".$ARGV[1]."\",1)");
}

print ", set to ".$db->selectrow_array(qq/select VALUESTRING from CONFIG where "KEYSTRING" == "$key"/)."\n" if $verbose;
$db->disconnect;
