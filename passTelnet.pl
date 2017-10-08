#!/usr/bin/perl
use strict;       
use Net::Telnet ();
use Getopt::Std;


my %opts;
getopts('t:s:h', \%opts);


my $target = $opts{'t'} if $opts{'t'};
my $software = $opts{'s'} if $opts{'s'};

sub usage
{
  printf "\nUsage :\n";
  printf "perl passTelnet.pl -t {ip} -s MikroTik \n\n";
  printf "";  
  exit(1);
}

# Print help message if required
if ($opts{'h'} || !(%opts)) {
	usage();
	exit 0;
}

my $t = new Net::Telnet (Timeout => 4);
$t->open($target);

if ($software eq "MikroTik")
{
    
  try {
   $t->login("admin", "");
  } catch{   
  }  
  print "MikroTik: Default password (admin:)\n";

}

