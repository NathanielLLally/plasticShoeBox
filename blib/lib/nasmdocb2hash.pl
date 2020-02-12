#!/usr/bin/perl

open(FH, "<nasmdocb.html") || die "open failed\n";

my (@hash, $link) = ( (), undef );
while (<FH>) {
  if (/(section-B\.4\.\d+)/gc) {
    $link = $1;
    @func = @hash = ();
    while (/(<code><nobr>(\w+)<\/nobr><\/code>,?)/gc) {
      unshift @hash, sprintf("%s%*s\t=> \\&exec%s,\n", lc $2, (10-length($2)), " ", uc $2);
      unshift @func, sprintf("sub exec%s(\$) {\n  my \$asm = shift;\n  DEBUG(\"***implement me '%%s'\\n\", \$asm->{insn});\n}\n", uc $2);
    }
    (/:\s(.*?)</gc) && push @func,
      sprintf("# %s [#%s]\n", $1, $link);
#  }
#  if (/\[.*?\d+86.*?\]/) {
    foreach (0..$#hash) {
      print STDOUT pop @hash;
    }
    foreach (0..$#func) {
      print STDERR pop @func;
    }
  }
}

close (FH);
