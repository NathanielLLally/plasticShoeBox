#! /usr/bin/perl

use ExtUtils::testlib;

use VirtualMachine;
use LogLevel;

#
# test of the stack and registers
#

tie (my %r, 'Registers', setname => 'general');
tie (my %s, 'Registers', setname => 'segment');
tie (my %f, 'Registers', setname => 'flags');
my $s = new Stack;

$r{eax} = 1234;
$r{eip} = hex '454740';

printf("start\tebp: %08x esp: %08x\n", $r{ebp}, $r{esp});

#imaginary stack
$s->push($r{eip});
$s->push($r{eax});
print "\t\t***pushed\teax: " . $r{eax} . " eip: " . sprintf("%08x",$r{eip}) . "\n";
printf("\tebp: %08x esp: %08x\n", $r{ebp}, $r{esp});

#proc someproc
$s->push($r{ebp});
$r{ebp} = $r{esp};
printf("in proc\tebp: %08x esp: %08x\n", $r{ebp}, $r{esp});

#do stuff
($r{eax}, $r{eip}) = (3579, hex '4555C0');

$s->push($r{eip});
$s->push($r{eax});
print "\t\t***pushed\teax: " . $r{eax} . " eip: " . sprintf("%08x",$r{eip}) . "\n";
printf("\tebp: %08x esp: %08x\n", $r{ebp}, $r{esp});

$r{eax} = $s->pop;
$r{eip} = $s->pop;
print "\t\t***popped\teax: " . $r{eax} . " eip: " . sprintf("%08x",$r{eip}) . "\n";
printf("\tebp: %08x esp: %08x\n", $r{ebp}, $r{esp});

$r{esp} = $r{ebp};
$r{ebp} = $s->pop('ebp');
#endp

printf("endp\tebp: %08x esp: %08x\n", $r{ebp}, $r{esp});

$r{eax} = $s->pop;
$r{eip} = $s->pop;
print "\t\t***popped\teax: " . $r{eax}
  . " eip: " . sprintf("%08x",$r{eip}) . "\n";

$s{cs} = hex 1234;
$f{of} = 1;
printf("cs: %s of: %s\n", sprintf("%04x",$s{cs}),
       ($f{of}) ? "on" : "off");

foreach (keys %r) {
  printf("%s ", $_);
}
printf("\n");
foreach (keys %s) {
  printf("%s ", $_);
}
printf("\n");
foreach (keys %f) {
  printf("%s ", $_);
}
printf("\n");

sub code(@) {
  my $a = shift || undef;
  return 1;
}

my (@array, %hash, $arrayref, $hashref, $coderef)
  = (() x 2, undef, undef, undef);

$arrayref = \@array;
printf("array ref: %s", ref $arrayref);
