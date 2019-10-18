#!/usr/bin/env perl
use strict; 
use warnings;
use Data::Dumper;
no warnings 'uninitialized';

my $names_file=$ARGV[0]; # format --> juan daniel torres sandi
 

open (MYINPUT,"<$names_file") || die "ERROR: Can not open the file $names_file\n";
while (my $line=<MYINPUT>)
{ 
$line =~ s/\n//g; 
$line =~ s/á/a/g; 
$line =~ s/é/e/g; 
$line =~ s/í/i/g; 
$line =~ s/ó/o/g; 
$line =~ s/ú/u/g;
$line =~ s/ñ/n/g;  

print $line,"\n";
my $name;
my $lastname1;
my $lastname2;

my @line_array = split(" ",$line);

#daniel torres sandi
if ($line_array[3] eq '')
{
	$name = lc($line_array[0]);
	$lastname1 = lc($line_array[1]);
	$lastname2 = lc($line_array[2]);
}
#juan daniel torres sandi
else
{
	$name = lc($line_array[0]);
	$lastname1 = lc($line_array[2]);
	$lastname2 = lc($line_array[3]);
}

my $initial1 = unpack('A1',$name);
my $initial2 = unpack('A1',$lastname1);
my $initial3 = unpack('A1',$lastname2);

# Daniel Torres Sandi


my $username1 = $initial1.$initial2.$initial3;# dts

my $username2 = $initial1.".".$lastname1;# d.torres
my $username3 = $initial1.$lastname1; #dtorres

my $username4 = $name.".".$initial2; #daniel.t
my $username5 = $name.$initial2; # danielt

my $username6 = $name.".".$lastname1; #daniel.torres
my $username7 = $name.$lastname1; # danieltorres

open (SALIDA,">>users.txt") || die "ERROR: No puedo abrir el fichero users.txt\n";
print SALIDA "$username1;$username2;$username3;$username4;$username5;$username6;$username7;$lastname1\n";
close (SALIDA);

}
