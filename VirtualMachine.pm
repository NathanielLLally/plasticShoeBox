# Nate Lally 06/2/04 nate[at]airitechsecurity[dot]com
#

=head1 NAME

VirtualMachine - binary analysis class

VirtualMachine components:
Cpu		- provides methods for execution
Stack		- implements a stack
Registers	- segment, general, fpu, eflags
DisAsm		- interface to ndisasm

=head1 SYNOPSIS
=head1 DESCRIPTION
=over 8
=back
=head1 EXAMPLE
=head1 BUGS
=head1 TODO
=head1 AUTHOR
Nate Lally	nate[at]airitechsecurity[dot]com

Copyright (c) 2004 Nate Lally. All rights reserved.
This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.
=head1 VERSION

Version 0.01    14 May, 2004
=head1 SEE ALSO
perl(1)

=cut

require 5.6.0;

package VirtualMachine;

use strict;
use warnings;
use LogLevel;

require Exporter;
require DynaLoader;

our @ISA = qw(DisAsm Exporter DynaLoader);
our @EXPORT = qw();
our @EXPORT_OK = qw();
our $VERSION = '0.05';

bootstrap VirtualMachine $VERSION;

sub boot(@);
sub parse($);
sub trace(;$);
sub executeInsn($);
sub displayState;

sub run($);
sub break($);
sub singleStep($);
sub stepInto($);

#private global block
{
  my (%r, %sr, %f) = ();

  my ($stack, $disasm) = ();
  my (%xref_from, %xref_to) = ((), ());

  sub boot(@) {
    my $proto = shift;
    my $class = ref($proto) || $proto;

    my $self = { %{ import_loglevel
		      ($class, DEBUG=>1, INFO=>1)
		  }, @_ };
    bless($self, $class);
    $self->{NOTICE}->("loading bootstrap...", undef, undef);
    tie (%r,  'Registers');
    tie (%sr, 'Registers', setname => 'segment');
    tie (%f,  'Registers', setname => 'flags');
    $self->{NOTICE}->("initialized cpu state", undef, undef);
    $stack = Stack->new();
    $disasm = DisAsm->new();

    (exists $self->{FILE})
      && $self->loadImage($self->{FILE});

    return $self;
  }

  sub displayState {
    my $self = shift;
  }

  #  parse(%{$instruction}) - parses ndisasm output
  #    into my %insn quasi-object
  #  handles symbol resolution, type/size qualification
  #
  ####################################################
  sub parse($) {
    my ($self, $nasm) = @_;
    my (%insn, %op) = ((), ());
    $insn{sz} = $nasm;
    if ($nasm =~ /^(\w+)\s?/gc) {
      $insn{sz} = $1;
      while ($nasm =~ /(([[:alnum:]\[\]\+\-\*:_\s\.?@\$<>()]+),?\s?)/gc) {
	%op = ( sz => $2 );
	if ($op{sz} =~ s/([dqt]?(word|byte|near|far))//) {
	  $op{mod} = $1;
	}

	#resolve address to de-reference
	$op{address} = 0;
	if ($op{sz} =~ s/\[(.*?)\]/$1/) {
	  while ($op{sz} =~ /(\+|\-)?(0x(\d|\w)+|\w+):?/gc) {
	    my ($op, $reg) = ($1 || '+', $2 || $3);
	    if (exists $r{$reg}) {
	      $op{address} = eval "$op{address} $op $r{$reg}";
	    } elsif (exists $sr{$reg}) {
	      $self->{DEBUG}->("segment %s ", $reg);
	    } else {
	      $op{address} = eval "$op{address} $op $reg";
	    }
	  }
	  $op{resolved} = dword($op{address});
	}
	push @{$insn{op}}, \%op;
      }
    } else {
      $self->{ERR}->("\n'%s'\nexcuse me, my right honorable friend, but i'm afraid i am not quite sure " .
		     "about how to proceed in order to parse the afformentioned instruction.\n", $nasm);
    }
    return \%insn;
  }

  # trace(;$offset) - what once was a american made v-12
  #   engine is now a japanese 4 cylinder
  # a glorified recursable while loop that is the glue
  #   of VirtualMachine components
  #####################################################
  sub trace(;$) {
    my ($self, $offset) = @_;
    my ($lendis, %insn, $done) = (0, {}, 0);

    $r{eip} = $offset || $disasm->entryPoint;
    if (defined $offset) {
      $self->{DEBUG}->("\nnew trace from %08x\n", $r{eip});
    } else {
      $self->{INFO}->("\nbeginning execution trace from %08x (entry point)\n", $r{eip});
    }

    while (not $done) {
      %insn = %{$disasm->disAssemble($r{eip})};
      ($insn{err} > 0) && $self->{ALERT}->("%s\n", undef, $insn{errstr});
      ($insn{err} < 0) && $self->{ERR}->("%s\n", undef, $insn{errstr});

      $self->{INFO}->("%08x    ", $r{eip});
      $self->{INFO}->("%s%*s", $insn{sz}, 30 - length $insn{sz}, " ");

      $r{eip} += $insn{len};

      $self->executeInsn($insn{sz});
      $self->{INFO}->("\n");
    }

    if (defined $offset) {
      $self->{DEBUG}->("\nend of trace from %08x\n", $offset);
    } else {
      $self->{INFO}->("\nend of execution trace\n", $r{eip});
    }
  }

  # ASCII Adjustments [#section-B.4.1]
  sub execAAA($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execAAS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execAAM($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execAAD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Add with Carry [#section-B.4.2]
  sub execADC($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Add Integers [#section-B.4.3]
  sub execADD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Bitwise AND [#section-B.4.8]
  sub execAND($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Adjust RPL Field of Selector [#section-B.4.13]
  sub execARPL($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Check Array Index against Bounds [#section-B.4.14]
  sub execBOUND($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Bit Scan [#section-B.4.15]
  sub execBSF($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execBSR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Byte Swap [#section-B.4.16]
  sub execBSWAP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Bit Test [#section-B.4.17]
  sub execBT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execBTC($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execBTR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execBTS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Call Subroutine [#section-B.4.18]
  sub execCALL($) {
    my ($s, $i) = (shift, shift);
    $stack->push($r{eip});
    $stack->push($sr{cs}) if ($i->{op}[0]{mod} eq 'far');
    $s->execJMP($i);
  }
  # Sign Extensions [#section-B.4.19]
  sub execCBW($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execCWD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execCDQ($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execCWDE($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Clear Flags [#section-B.4.20]
  sub execCLC($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execCLD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execCLI($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execCLTS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Complement Carry Flag [#section-B.4.22]
  sub execCMC($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Compare Integers [#section-B.4.24]
  sub execCMP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Compare Strings [#section-B.4.27]
  sub execCMPSB($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execCMPSW($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execCMPSD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Compare and Exchange [#section-B.4.30]
  sub execCMPXCHG($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execCMPXCHG486($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Decimal Adjustments [#section-B.4.57]
  sub execDAA($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execDAS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Decrement Integer [#section-B.4.58]
  sub execDEC($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Unsigned Integer Divide [#section-B.4.59]
  sub execDIV($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Create Stack Frame [#section-B.4.65]
  sub execENTER($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Calculate 2**X-1 [#section-B.4.66]
  sub execF2XM1($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point Absolute Value [#section-B.4.67]
  sub execFABS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point Addition [#section-B.4.68]
  sub execFADD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFADDP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # BCD Floating-Point Load and Store [#section-B.4.69]
  sub execFBLD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFBSTP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point Change Sign [#section-B.4.70]
  sub execFCHS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Clear Floating-Point Exceptions [#section-B.4.71]
  sub execFCLEX($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFNCLEX($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point Compare [#section-B.4.73]
  sub execFCOM($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFCOMP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFCOMPP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFCOMI($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFCOMIP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Cosine [#section-B.4.74]
  sub execFCOS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Decrement Floating-Point Stack Pointer [#section-B.4.75]
  sub execFDECSTP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Disable and Enable Floating-Point Interrupts [#section-B.4.76]
  sub execFXDISI($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFXENI($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point Division [#section-B.4.77]
  sub execFDIV($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFDIVP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFDIVR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFDIVRP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Flag Floating-Point Register as Unused [#section-B.4.79]
  sub execFFREE($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point/Integer Addition [#section-B.4.80]
  sub execFIADD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point/Integer Compare [#section-B.4.81]
  sub execFICOM($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFICOMP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point/Integer Division [#section-B.4.82]
  sub execFIDIV($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFIDIVR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point/Integer Conversion [#section-B.4.83]
  sub execFILD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFIST($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFISTP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point/Integer Multiplication [#section-B.4.84]
  sub execFIMUL($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Increment Floating-Point Stack Pointer [#section-B.4.85]
  sub execFINCSTP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Initialise Floating-Point Unit [#section-B.4.86]
  sub execFINIT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFNINIT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point/Integer Subtraction [#section-B.4.87]
  sub execFISUB($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point Load [#section-B.4.88]
  sub execFLD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point Load Constants [#section-B.4.89]
  sub execFLDXX($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Load Floating-Point Control Word [#section-B.4.90]
  sub execFLDCW($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Load Floating-Point Environment [#section-B.4.91]
  sub execFLDENV($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point Multiply [#section-B.4.92]
  sub execFMUL($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFMULP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point No Operation [#section-B.4.93]
  sub execFNOP($) {
    my ($s, $i) = (shift, shift);
  }
  # Arctangent and Tangent [#section-B.4.94]
  sub execFPATAN($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFPTAN($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point Partial Remainder [#section-B.4.95]
  sub execFPREM($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFPREM1($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point Round to Integer [#section-B.4.96]
  sub execFRNDINT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Save/Restore Floating-Point State [#section-B.4.97]
  sub execFSAVE($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFRSTOR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Scale Floating-Point Value by Power of Two [#section-B.4.98]
  sub execFSCALE($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Set Protected Mode [#section-B.4.99]
  sub execFSETPM($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Sine and Cosine [#section-B.4.100]
  sub execFSIN($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFSINCOS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point Square Root [#section-B.4.101]
  sub execFSQRT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point Store [#section-B.4.102]
  sub execFST($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFSTP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Store Floating-Point Control Word [#section-B.4.103]
  sub execFSTCW($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Store Floating-Point Environment [#section-B.4.104]
  sub execFSTENV($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Store Floating-Point Status Word [#section-B.4.105]
  sub execFSTSW($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point Subtract [#section-B.4.106]
  sub execFSUB($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFSUBP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFSUBR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFSUBRP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Test ST0 Against Zero [#section-B.4.107]
  sub execFTST($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point Unordered Compare [#section-B.4.108]
  sub execFUCOMXX($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Examine Class of Value in ST0 [#section-B.4.109]
  sub execFXAM($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Floating-Point Exchange [#section-B.4.110]
  sub execFXCH($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Extract Exponent and Significand [#section-B.4.113]
  sub execFXTRACT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Compute Y times Log2(X) or Log2(X+1) [#section-B.4.114]
  sub execFYL2X($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execFYL2XP1($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Halt Processor [#section-B.4.115]
  sub execHLT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Insert Bit String [#section-B.4.116]
  sub execIBTS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Signed Integer Divide [#section-B.4.117]
  sub execIDIV($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Signed Integer Multiply [#section-B.4.118]
  sub execIMUL($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Input from I/O Port [#section-B.4.119]
  sub execIN($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Increment Integer [#section-B.4.120]
  sub execINC($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Input String from I/O Port [#section-B.4.121]
  sub execINSB($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execINSW($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execINSD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Software Interrupt [#section-B.4.122]
  sub execINT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Breakpoints [#section-B.4.123]
  sub execINT3($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execINT1($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execICEBP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execINT01($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Interrupt if Overflow [#section-B.4.124]
  sub execINTO($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Invalidate Internal Caches [#section-B.4.125]
  sub execINVD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Invalidate TLB Entry [#section-B.4.126]
  sub execINVLPG($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Return from Interrupt [#section-B.4.127]
  sub execIRET($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execIRETW($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execIRETD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Conditional Branch [#section-B.4.128]
  # * O is 0 (trigger if the overflow flag is set); NO is 1.
  # * B, C and NAE are 2 (trigger if the carry flag is set); AE, NB and
  #   NC are 3.
  # * E and Z are 4 (trigger if the zero flag is set); NE and NZ are 5.
  # * BE and NA are 6 (trigger if either of the carry or zero flags is
  #   set); A and NBE are 7.
  # * S is 8 (trigger if the sign flag is set); NS is 9.
  # * P and PE are 10 (trigger if the parity flag is set); NP and PO are
  #   11.
  # * L and NGE are 12 (trigger if exactly one of the sign and overflow
  #   flags is set); GE and NL are 13.
  # * LE and NG are 14 (trigger if either the zero flag is set, or
  #   exactly one of the sign and overflow flags is set); G and NLE are
  #   15.
  sub execJCC($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Jump if CX/ECX Zero [#section-B.4.129]
  sub execJCXZ($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execJECXZ($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Jump [#section-B.4.130]
  sub execJMP($) {
    my ($s, $i) = (shift, shift);
    $xref_from{$r{eip}} = $i->{op}[0]{address};
    $xref_to{$i->{op}[0]{address}} = $r{eip};
    $s->{DEBUG}->("jumping to address %08x", $i->{op}[0]{address});
    $r{eip} = $i->{op}[0]{address};
  }
  # Load AH from Flags [#section-B.4.131]
  sub execLAHF($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Load Access Rights [#section-B.4.132]
  sub execLAR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Load Far Pointer [#section-B.4.134]
  sub execLDS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execLES($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execLFS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execLGS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execLSS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Load Effective Address [#section-B.4.135]
  sub execLEA($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Destroy Stack Frame [#section-B.4.136]
  sub execLEAVE($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Load Descriptor Tables [#section-B.4.138]
  sub execLGDT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execLIDT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execLLDT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Load/Store Machine Status Word [#section-B.4.139]
  sub execLMSW($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Load Processor State [#section-B.4.140]
  sub execLOADALL($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execLOADALL286($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Load from String [#section-B.4.141]
  sub execLODSB($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execLODSW($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execLODSD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Loop with Counter [#section-B.4.142]
  sub execLOOP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execLOOPE($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execLOOPZ($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execLOOPNE($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execLOOPNZ($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Load Segment Limit [#section-B.4.143]
  sub execLSL($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Load Task Register [#section-B.4.144]
  sub execLTR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Move Data [#section-B.4.156]
  sub execMOV($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Move String [#section-B.4.178]
  sub execMOVSB($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execMOVSW($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execMOVSD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Move Data with Sign or Zero Extend [#section-B.4.181]
  sub execMOVSX($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execMOVZX($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Unsigned Integer Multiply [#section-B.4.184]
  sub execMUL($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Two's and One's Complement [#section-B.4.189]
  sub execNEG($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execNOT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # No Operation [#section-B.4.190]
  sub execNOP($) {
  }
  # Bitwise OR [#section-B.4.191]
  sub execOR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Output Data to I/O Port [#section-B.4.194]
  sub execOUT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Output String to I/O Port [#section-B.4.195]
  sub execOUTSB($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execOUTSW($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execOUTSD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Pop Data from Stack [#section-B.4.244]
  sub execPOP($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Pop All General-Purpose Registers [#section-B.4.245]
  sub execPOPAX($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Pop Flags Register [#section-B.4.246]
  sub execPOPFX($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Push Data on Stack [#section-B.4.263]
  sub execPUSH($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Push All General-Purpose Registers [#section-B.4.264]
  sub execPUSHAX($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Push Flags Register [#section-B.4.265]
  sub execPUSHFX($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Bitwise Rotate through Carry Bit [#section-B.4.267]
  sub execRCL($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execRCR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Read SMM Header Pointer Register [#section-B.4.272]
  sub execRDSHR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Return from Procedure Call [#section-B.4.274]
  sub execRET($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execRETF($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execRETN($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Bitwise Rotate [#section-B.4.275]
  sub execROL($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execROR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Restore Segment Register and Descriptor [#section-B.4.276]
  sub execRSDC($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Restore Segment Register and Descriptor [#section-B.4.277]
  sub execRSLDT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Restore TSR and Descriptor [#section-B.4.281]
  sub execRSTS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Store AH to Flags [#section-B.4.282]
  sub execSAHF($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Bitwise Arithmetic Shifts [#section-B.4.283]
  sub execSAL($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execSAR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Set AL from Carry Flag [#section-B.4.284]
  sub execSALC($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Subtract with Borrow [#section-B.4.285]
  sub execSBB($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Scan String [#section-B.4.286]
  sub execSCASB($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execSCASW($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execSCASD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Set Register from Condition [#section-B.4.287]
  sub execSETCC($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Store Descriptor Table Pointers [#section-B.4.289]
  sub execSGDT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execSIDT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execSLDT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Bitwise Logical Shifts [#section-B.4.290]
  sub execSHL($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execSHR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Bitwise Double-Precision Shifts [#section-B.4.291]
  sub execSHLD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execSHRD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # System Management Interrupt [#section-B.4.294]
  sub execSMI($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Software SMM Entry (CYRIX) [#section-B.4.295]
  sub execSMINT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execSMINTOLD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Store Machine Status Word [#section-B.4.296]
  sub execSMSW($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Set Flags [#section-B.4.301]
  sub execSTC($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execSTD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execSTI($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Store Byte to String [#section-B.4.303]
  sub execSTOSB($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execSTOSW($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execSTOSD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Store Task Register [#section-B.4.304]
  sub execSTR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Subtract Integers [#section-B.4.305]
  sub execSUB($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Save Segment Register and Descriptor [#section-B.4.310]
  sub execSVDC($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Save LDTR and Descriptor [#section-B.4.311]
  sub execSVLDT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Save TSR and Descriptor [#section-B.4.312]
  sub execSVTS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Test Bits (notional bitwise AND) [#section-B.4.317]
  sub execTEST($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Undefined Instruction [#section-B.4.320]
  sub execUD0($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execUD1($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execUD2($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # User Move Data [#section-B.4.321]
  sub execUMOV($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Verify Segment Readability/Writability [#section-B.4.326]
  sub execVERR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  sub execVERW($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Wait for Floating-Point Processor [#section-B.4.327]
  sub execWAIT($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Write Back and Invalidate Cache [#section-B.4.328]
  sub execWBINVD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Write SMM Header Pointer Register [#section-B.4.330]
  sub execWRSHR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Exchange and Add [#section-B.4.331]
  sub execXADD($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Extract Bit String [#section-B.4.332]
  sub execXBTS($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Exchange [#section-B.4.333]
  sub execXCHG($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Translate Byte in Lookup Table [#section-B.4.334]
  sub execXLATB($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }
  # Bitwise Exclusive OR [#section-B.4.335]
  sub execXOR($) {
    my ($s, $i) = (shift, shift);
    $s->{DEBUG}->("***implement me '%s'", $i->{sz});
  }

  sub executeInsn($) {
    my ($self, $nasm) = (shift, shift);
    my %instruction_map =
      (aaa       	=> \&execAAA,
       aas       	=> \&execAAS,
       aam       	=> \&execAAM,
       aad       	=> \&execAAD,
       adc       	=> \&execADC,
       add       	=> \&execADD,
       and       	=> \&execAND,
       arpl      	=> \&execARPL,
       bound     	=> \&execBOUND,
       bsf       	=> \&execBSF,
       bsr       	=> \&execBSR,
       bswap     	=> \&execBSWAP,
       bt        	=> \&execBT,
       btc       	=> \&execBTC,
       btr       	=> \&execBTR,
       bts       	=> \&execBTS,
       call      	=> \&execCALL,
       cbw       	=> \&execCBW,
       cwd       	=> \&execCWD,
       cdq       	=> \&execCDQ,
       cwde      	=> \&execCWDE,
       clc       	=> \&execCLC,
       cld       	=> \&execCLD,
       cli       	=> \&execCLI,
       clts      	=> \&execCLTS,
       cmc       	=> \&execCMC,
       cmp       	=> \&execCMP,
       cmpsb     	=> \&execCMPSB,
       cmpsw     	=> \&execCMPSW,
       cmpsd     	=> \&execCMPSD,
       cmpxchg   	=> \&execCMPXCHG,
       cmpxchg486 	=> \&execCMPXCHG486,
       daa       	=> \&execDAA,
       das       	=> \&execDAS,
       dec       	=> \&execDEC,
       div       	=> \&execDIV,
       db		=> \&execNOP,
       enter     	=> \&execENTER,
       f2xm1     	=> \&execF2XM1,
       fabs      	=> \&execFABS,
       fadd      	=> \&execFADD,
       faddp     	=> \&execFADDP,
       fbld      	=> \&execFBLD,
       fbstp     	=> \&execFBSTP,
       fchs      	=> \&execFCHS,
       fclex     	=> \&execFCLEX,
       fnclex    	=> \&execFNCLEX,
       fcom      	=> \&execFCOM,
       fcomp     	=> \&execFCOMP,
       fcompp    	=> \&execFCOMPP,
       fcomi     	=> \&execFCOMI,
       fcomip    	=> \&execFCOMIP,
       fcos      	=> \&execFCOS,
       fdecstp   	=> \&execFDECSTP,
       fxdisi    	=> \&execFXDISI,
       fxeni     	=> \&execFXENI,
       fdiv      	=> \&execFDIV,
       fdivp     	=> \&execFDIVP,
       fdivr     	=> \&execFDIVR,
       fdivrp    	=> \&execFDIVRP,
       ffree     	=> \&execFFREE,
       fiadd     	=> \&execFIADD,
       ficom     	=> \&execFICOM,
       ficomp    	=> \&execFICOMP,
       fidiv     	=> \&execFIDIV,
       fidivr    	=> \&execFIDIVR,
       fild      	=> \&execFILD,
       fist      	=> \&execFIST,
       fistp     	=> \&execFISTP,
       fimul     	=> \&execFIMUL,
       fincstp   	=> \&execFINCSTP,
       finit     	=> \&execFINIT,
       fninit    	=> \&execFNINIT,
       fisub     	=> \&execFISUB,
       fld       	=> \&execFLD,
       fldxx     	=> \&execFLDXX,
       fldcw     	=> \&execFLDCW,
       fldenv    	=> \&execFLDENV,
       fmul      	=> \&execFMUL,
       fmulp     	=> \&execFMULP,
       fnop      	=> \&execFNOP,
       fpatan    	=> \&execFPATAN,
       fptan     	=> \&execFPTAN,
       fprem     	=> \&execFPREM,
       fprem1    	=> \&execFPREM1,
       frndint   	=> \&execFRNDINT,
       fsave     	=> \&execFSAVE,
       frstor    	=> \&execFRSTOR,
       fscale    	=> \&execFSCALE,
       fsetpm    	=> \&execFSETPM,
       fsin      	=> \&execFSIN,
       fsincos   	=> \&execFSINCOS,
       fsqrt     	=> \&execFSQRT,
       fst       	=> \&execFST,
       fstp      	=> \&execFSTP,
       fstcw     	=> \&execFSTCW,
       fstenv    	=> \&execFSTENV,
       fstsw     	=> \&execFSTSW,
       fsub      	=> \&execFSUB,
       fsubp     	=> \&execFSUBP,
       fsubr     	=> \&execFSUBR,
       fsubrp    	=> \&execFSUBRP,
       ftst      	=> \&execFTST,
       fucomxx   	=> \&execFUCOMXX,
       fxam      	=> \&execFXAM,
       fxch      	=> \&execFXCH,
       fxtract   	=> \&execFXTRACT,
       fyl2x     	=> \&execFYL2X,
       fyl2xp1   	=> \&execFYL2XP1,
       hlt       	=> \&execHLT,
       ibts      	=> \&execIBTS,
       idiv      	=> \&execIDIV,
       imul      	=> \&execIMUL,
       in        	=> \&execIN,
       inc       	=> \&execINC,
       insb      	=> \&execINSB,
       insw      	=> \&execINSW,
       insd      	=> \&execINSD,
       int       	=> \&execINT,
       int3      	=> \&execINT3,
       int1      	=> \&execINT1,
       icebp     	=> \&execICEBP,
       int01     	=> \&execINT01,
       into      	=> \&execINTO,
       invd      	=> \&execINVD,
       invlpg    	=> \&execINVLPG,
       iret      	=> \&execIRET,
       iretw     	=> \&execIRETW,
       iretd     	=> \&execIRETD,
       jo       	=> \&execJCC,
       jno       	=> \&execJCC,
       jc       	=> \&execJCC,
       jnc       	=> \&execJCC,
       jz       	=> \&execJCC,
       jnz       	=> \&execJCC,
       jna       	=> \&execJCC,
       ja       	=> \&execJCC,
       js       	=> \&execJCC,
       jns       	=> \&execJCC,
       jpe       	=> \&execJCC,
       jpo       	=> \&execJCC,
       jl       	=> \&execJCC,
       jnl       	=> \&execJCC,
       jng       	=> \&execJCC,
       jg       	=> \&execJCC,
       jcxz      	=> \&execJCXZ,
       jecxz     	=> \&execJECXZ,
       jmp       	=> \&execJMP,
       lahf      	=> \&execLAHF,
       lar       	=> \&execLAR,
       lds       	=> \&execLDS,
       les       	=> \&execLES,
       lfs       	=> \&execLFS,
       lgs       	=> \&execLGS,
       lss       	=> \&execLSS,
       lea       	=> \&execLEA,
       leave     	=> \&execLEAVE,
       lgdt      	=> \&execLGDT,
       lidt      	=> \&execLIDT,
       lldt      	=> \&execLLDT,
       lmsw      	=> \&execLMSW,
       loadall   	=> \&execLOADALL,
       loadall286 	=> \&execLOADALL286,
       lodsb     	=> \&execLODSB,
       lodsw     	=> \&execLODSW,
       lodsd     	=> \&execLODSD,
       loop      	=> \&execLOOP,
       loope     	=> \&execLOOPE,
       loopz     	=> \&execLOOPZ,
       loopne    	=> \&execLOOPNE,
       loopnz    	=> \&execLOOPNZ,
       lsl       	=> \&execLSL,
       ltr       	=> \&execLTR,
       mov       	=> \&execMOV,
       movsb     	=> \&execMOVSB,
       movsw     	=> \&execMOVSW,
       movsd     	=> \&execMOVSD,
       movsx     	=> \&execMOVSX,
       movzx     	=> \&execMOVZX,
       mul       	=> \&execMUL,
       neg       	=> \&execNEG,
       not       	=> \&execNOT,
       nop       	=> \&execNOP,
       or        	=> \&execOR,
       out       	=> \&execOUT,
       outsb     	=> \&execOUTSB,
       outsw     	=> \&execOUTSW,
       outsd     	=> \&execOUTSD,
       pop       	=> \&execPOP,
       popax     	=> \&execPOPAX,
       popfx     	=> \&execPOPFX,
       push      	=> \&execPUSH,
       pushax    	=> \&execPUSHAX,
       pushfx    	=> \&execPUSHFX,
       rcl       	=> \&execRCL,
       rcr       	=> \&execRCR,
       rdshr     	=> \&execRDSHR,
       ret       	=> \&execRET,
       retf      	=> \&execRETF,
       retn      	=> \&execRETN,
       rol       	=> \&execROL,
       ror       	=> \&execROR,
       rsdc      	=> \&execRSDC,
       rsldt     	=> \&execRSLDT,
       rsts      	=> \&execRSTS,
       sahf      	=> \&execSAHF,
       sal       	=> \&execSAL,
       sar       	=> \&execSAR,
       salc      	=> \&execSALC,
       sbb       	=> \&execSBB,
       scasb     	=> \&execSCASB,
       scasw     	=> \&execSCASW,
       scasd     	=> \&execSCASD,
       setcc     	=> \&execSETCC,
       sgdt      	=> \&execSGDT,
       sidt      	=> \&execSIDT,
       sldt      	=> \&execSLDT,
       shl       	=> \&execSHL,
       shr       	=> \&execSHR,
       shld      	=> \&execSHLD,
       shrd      	=> \&execSHRD,
       smi       	=> \&execSMI,
       smint     	=> \&execSMINT,
       smintold  	=> \&execSMINTOLD,
       smsw      	=> \&execSMSW,
       stc       	=> \&execSTC,
       std       	=> \&execSTD,
       sti       	=> \&execSTI,
       stosb     	=> \&execSTOSB,
       stosw     	=> \&execSTOSW,
       stosd     	=> \&execSTOSD,
       str       	=> \&execSTR,
       sub       	=> \&execSUB,
       svdc      	=> \&execSVDC,
       svldt     	=> \&execSVLDT,
       svts      	=> \&execSVTS,
       test      	=> \&execTEST,
       ud0       	=> \&execUD0,
       ud1       	=> \&execUD1,
       ud2       	=> \&execUD2,
       umov      	=> \&execUMOV,
       verr      	=> \&execVERR,
       verw      	=> \&execVERW,
       wait      	=> \&execWAIT,
       wbinvd    	=> \&execWBINVD,
       wrshr     	=> \&execWRSHR,
       xadd      	=> \&execXADD,
       xbts      	=> \&execXBTS,
       xchg      	=> \&execXCHG,
       xlatb     	=> \&execXLATB,
       xor       	=> \&execXOR,
      );

    my $insn = $self->parse($nasm);

    if (exists $instruction_map{$insn->{sz}}) {
      my $coderef = $instruction_map{$insn->{sz}};

      if (ref $coderef eq 'CODE') {
	my $ret = $coderef->($self, $insn);
	return $ret if (defined $ret);
      } else {
	die "stop messing up my instruction callback lookup hash!\n";
      }

    } else {
      $self->{ERR}->("unknown instruction '%s'\n", undef, $insn->{sz});
    }
  }
}

##############################################################
package Stack;

use strict;
use warnings;
use LogLevel;

require Exporter;
require DynaLoader;

our @ISA = qw(Exporter DynaLoader);
our @EXPORT_OK = qw();
our $VERSION = '0.01';

sub new(;@);
sub alloc;
sub DESTROY();
sub push($);
sub pop;

# Preloaded methods go here.
sub new(;@) {
  my $proto = shift;
  my $class = ref($proto) || $proto;

  my $self = { SIZE => 32767,
	       %{import_loglevel($class)},
	       @_ };

  bless($self, $class);

  $self->alloc;
  $self->{NOTICE}->("initialised stack (size %u)",
		    undef, $self->{SIZE});

  return $self;
}

sub DESTROY() {
  my $self = shift;
  $self->cleanup();
}

sub push($) {
  my ($self, $reg) = (shift, shift);
  return $self->push32($reg);
}

sub pop() {
  my $self = shift;
  return $self->pop32();
}

##############################################################
package Registers;

use strict;
use warnings;
use integer;
use Tie::IxHash;

require Tie::Hash;
require Exporter;
require DynaLoader;

our @ISA = qw(Exporter DynaLoader Tie::Hash);
our @EXPORT_OK = qw();
our $VERSION = '0.01';

#tie(%hash, 'Registers', 'type', 'segwidth')
# type = (segment|general|flags|fpu) || general
# segwidth = (16|32) || 32
# rettype = (IV | PV) integer value, pointer value
#                       string is converted to hex
sub TIEHASH(;@) {
  my $proto = shift;
  my $class = ref($proto) || $proto;
  my %self = %{{ ( segwidth => 32,
		   setname => 'general',
		   rettype => 'IV'
		 ), @_ }};

  #defaults and parameter bounds checking
  my $segwidth = \$self{segwidth};

  tie(%{$self{segment}[0]}, 'Tie::IxHash',
      cs => $segwidth, ds => $segwidth, es => $segwidth,
      fs => $segwidth, gs => $segwidth, ss => $segwidth
     );
  push @{$self{segment}}, \&get_reg;
  push @{$self{segment}}, \&set_reg;

  tie(%{$self{general}[0]}, 'Tie::IxHash',
      eax => 32, ebx => 32, ecx => 32, edx => 32, esi => 32,
      edi => 32, ebp => 32, esp => 32, eip => 32,
      ax => 16, bx => 16, cx => 16, dx => 16, si => 16,
      di => 16, bp => 16, sp => 16, ip => 16,
      al => 8, ah => 8, bl => 8, bh => 8,
      cl => 8, ch => 8, dl => 8, dh => 8
     );
  push @{$self{general}}, \&get_reg;
  push @{$self{general}}, \&set_reg;

  tie(%{$self{flags}[0]}, 'Tie::IxHash',
      cf => 1, pf => 1, af => 1, zf => 1, sf => 1,
      tf => 1, if => 1, df => 1, of => 1,
      iopl => 1, nt => 1, rf => 1, vm => 1,
      ac => 1, vf => 1, vp => 1, id =>1
     );
  push @{$self{flags}}, sub {
    my $k = shift;
    $self{_flags}[0]->{$k};
  };
  push @{$self{flags}}, sub {
    my ($k, $v) = (shift, shift);
    $self{_flags}[0]->{$k} = $v;
  };

  $self{cset} = \%{$self{$self{setname}}[0]};
  $self{names} = [keys %{$self{$self{setname}}[0]}];
  $self{fetch} = $self{$self{setname}}[1];
  $self{store} = $self{$self{setname}}[2];
  $self{iter} = 0;

  bless(\%self, $class);
  return \%self;
}

#sub DESTROY() {}

sub FETCH {
  my($s, $k) = (shift, lc shift);
  if (exists $s->{cset}{$k}) {
    my $r = $s->{fetch}->($k);
    return ($s->{rettype} eq 'IV') ? $r
      : sprintf("0x%0*x", $s->bitwidth($k) / 4, $r);
  } else {
    return undef;
  }
}

sub STORE {
  my($s, $k, $v) = (shift, lc shift, shift);
  return if (not defined $k or not defined $v);
  $s->{store}->($k, $v) if (exists $s->{cset}{$k});
}

#set to 0
sub DELETE {
  my($s, $k) = (shift, lc shift);
  $s->{store}->($k, 0) if (exists $s->{cset}{$k});
}

#is this key a cset token from set?
sub EXISTS {
  my($s, $k) = (shift, lc shift);
  return (exists $s->{cset}{$k});
}

#iterate over keys in current set
sub FIRSTKEY {
  my $s = shift;
  $s->{iter} = 0;
  $s->NEXTKEY;
}

sub NEXTKEY {
  my ($s, $last) = (shift, shift);
  return $s->{names}[$s->{iter}++] if ($s->{iter} <= $#{$s->{names}});
  return undef;
}

#provide some ancillary methods
sub new { TIEHASH(@_) }

sub bitwidth {
  my ($s, $k) = (shift, shift);
  return ($s->{cset}{$k}) if (exists $s->{cset}{$k});
}

sub size {
  my ($s, $k) = (shift, shift);
  return (size_bits_2way($s->{cset}{$k}))
	  if (exists $s->{cset}{$k});
}

###############################################################
package DisAsm;

use strict;
use warnings;
use LogLevel;

require Exporter;
require DynaLoader;

our @ISA = qw(Exporter DynaLoader);
our @EXPORT_OK = qw(loadImage);
our $VERSION = '0.01';

sub loadImage($);

sub new(@) {
  my $proto = shift;
  my $class = ref($proto) || $proto;

  my $self = { %{import_loglevel($class)},
	       @_ };
  bless($self, $class);

  (exists $self->{FILE})
    && $self->loadImage($self->{FILE});

  return $self;
}

sub DESTROY() {
  my $self = shift;
  $self->cleanup();
}

# Autoload methods go after __END__, and are processed by the autosplit program.
1;
__END__
