#! /usr/bin/perl

use ExtUtils::testlib;

use strict;
use warnings;

use LogLevel;
LOG_ON($LOG_DEBUG);
#$LOG_FUNC{EMERG} = undef; #sub {printf("\nhalt: %s\n", shift);};
#$LOG_FUNC{DEBUG} = undef;
DEBUG("...%u\n", $LOG_DEBUG);
EMERG("test");
DEBUG("hmmm...");
