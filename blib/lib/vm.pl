#! /usr/bin/perl

use ExtUtils::testlib;

use VirtualMachine;
use LogLevel;

#use IO::Pager;
#use Tk;

#my $main = MainWindow->new*(;
#my $menubar = $main->Frame(-relief	=> 'raised',
#			   -borderwidth => 2,
#			  );

$| = 1;
#  local $STDOUT = new IO::Pager::Unbuffered *STDOUT;
  my $vm = VirtualMachine->boot();
  $vm->loadImage($ARGV[0]);
  $vm->printFileStats;
  $vm->trace;
