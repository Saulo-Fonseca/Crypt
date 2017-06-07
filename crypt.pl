#!/usr/bin/perl
# Author: Saulo Fonseca
# Description: Encrypt/decrypt a file using SHA512 and own algorithm

use Digest::SHA "sha512";	# Load hash module
use Term::ReadKey;		# Load keymode module
use POSIX;			# Floor; Strftime

# Test argument
if (@ARGV != 1)
{
	print "\n";
	print "   This is a utility to encrypt/decrypt files using SHA256\n";
	print "   It adds .crypt to a copy of the file (or removes if decrypt)\n";
	print "   Usage: perl crypt.pl filename\n";
	die   "          perl crypt.pl filename.crypt\n\n";
}

# Open file for read
my $file = @ARGV[0];
open(SOURCE,"<".$file) or die "$file: $!\n";
binmode SOURCE;
my $filesize = -s $file;

# Read password
print "Password: ";
ReadMode('noecho');
chomp($pass = <STDIN>);
ReadMode('restore');
print "\n";
my $startTime = time();	# Starts counting the time

# Hash password
my $hash = sha512($pass);
my $hashlen = length($hash);

# Change hashlen after password
$sumpass = 0;
$passlen = length($hash);
for (my $i=0; $i<$passlen; $i++)
{
	$sumpass += ord(substr($pass,$i,1));
}
$hashlen = floor($hashlen/2);
$hashlen += $sumpass%$hashlen; # hashlen will vary from 32 to 64 bytes

# Adjust output name
my $filelen = length($file);
if (substr($file,$filelen-6,6) eq ".crypt")
{
	$file = substr($file,0,$filelen-6),"\n";
}
else
{
	$file .= ".crypt";
}
print $file,"\n";

# Open file for write
open(DESTINATION,">".$file) or die "$file: $!\n";
binmode DESTINATION;

# Read input file and XOR every byte with hash
my $count = 0;
my $sofar = 0;
my $lastperc = -1;
while(sysread(SOURCE,$byte,1))
{
	my $byteOrd = ord($byte);			# Get ASCII value of file
	my $hashOrd = ord(substr($hash,$count,1));	# Get ASCII value of hash
	my $xor = $byteOrd ^ $hashOrd;			# XOR both
	print DESTINATION chr($xor);
	$count++;
	$sofar++;
	if ($count == $hashlen)
	{
		$count = 0;
		my $perc = floor($sofar*100/$filesize);
		if ($lastperc != $perc && $perc%5 == 0 && perc != 100)
		{
			$lastperc = $perc;
			print "$perc%\n";
		}
	}
}
print "100%\n";

# Close files
close SOURCE or die "$!\n";
close DESTINATION or die "$!\n";
print strftime("Duration: \%H:\%M:\%S\n", gmtime(time()-$startTime));
