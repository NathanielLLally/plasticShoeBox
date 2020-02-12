#! /usr/bin/perl

use ExtUtils::testlib;

use VirtualMachine;

tie (my %r, 'Registers');
my $s = new Stack;
my $d = new DisAsm;
my $lendis;

$d->loadFile($ARGV[0]);
$r{'eip'} = $d->entryPoint;

printf("entry point: %08x\n", $r{'eip'});
my $da;

foreach (1..100) {
  $da = $d->disAssemble($r{'eip'});

  printf("%08x\t", $r{'eip'});
  foreach(1..$da->{'len'}) {
    printf("%x", $da->{'bytes'}[$_-1]);
  }
  printf("%*s\t", (15 - $da->{'len'}), "");
  printf("%s\n", $da->{'asm'});

  $r{'eip'} += $da->{'len'};
}
