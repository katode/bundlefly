#!/usr/bin/perl
#
# Uses the openssl command to decode what appears to be PEM certificates on stdin, and lists some info.
#   cat myx509certbundle.pem | certdump.pl
#
use strict;
use warnings;

use IPC::Open3;
use IO::Select;
use Symbol 'gensym';
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);


### Use non-blocking I/O for stdin/stdout to avoid temp files
sub run_with_input {
  my ($cmd, $input) = @_;

  # $cmd can be arrayref or string
  my @cmd = ref $cmd eq 'ARRAY' ? @$cmd : ($cmd);

  my ($stdin, $stdout, $stderr);
  $stderr = gensym;

  my $pid = open3($stdin, $stdout, $stderr, @cmd);

  # Make stdout/stderr non-blocking
  for my $fh ($stdout, $stderr) {
    my $flags = fcntl($fh, F_GETFL, 0);
    fcntl($fh, F_SETFL, $flags | O_NONBLOCK);
  }

  my $sel_read  = IO::Select->new($stdout, $stderr);
  my $sel_write = IO::Select->new($stdin);

  my ($out, $err) = ('', '');
  my $input_pos = 0;
  my $input_len = length($input // '');

  while ($sel_read->count || $sel_write->count) {
    my ($can_read, $can_write) = IO::Select->select(
      $sel_read, $sel_write, undef, 1
        );

    # Write input without blocking
    for my $fh (@{$can_write || []}) {
      my $written = syswrite($fh, $input, 4096, $input_pos);
      if (defined $written) {
        $input_pos += $written;
        if ($input_pos >= $input_len) {
          close $stdin;
          $sel_write->remove($fh);
        }
      }
    }

    # Read output without blocking
    for my $fh (@{$can_read || []}) {
      my $bytes = sysread($fh, my $buf, 4096);
      if (!$bytes) {
        $sel_read->remove($fh);
        next;
      }
      if ($fh eq $stdout) {
        $out .= $buf;
      } else {
        $err .= $buf;
      }
    }
  }

  waitpid($pid, 0);
  my $exit_code = $? >> 8;

  return ($exit_code, $out, $err);
}


#
# MAIN
#
{
  my $inside = 0;
  my $current = '';
  my @certs;

  # Do we want to grep for a specific subject?
  my $subject_grep_arg = undef;
  if (defined($ARGV[0]) and $ARGV[0] =~ m,\S,) {
    $subject_grep_arg = quotemeta($ARGV[0]);
  }

  # Separate certificate chain into single PEM blobs
  while (defined($_ = <STDIN>)) {
    s,^\s+,,;
    s,\s+$,,;

    if (m,^-----BEGIN CERTIFICATE-----$,) {
      $inside = 1;
    }

    $current .= $_ . "\n" if $inside;

    if (m,^-----END CERTIFICATE-----$,) {
      push(@certs, $current);
      $current = '';
      $inside = 0;
    }
  }

  # Decode with openssl
  my $exts = "subjectKeyIdentifier,authorityKeyIdentifier,subjectAltName";
  my @run_cmd = (qw(openssl x509 -noout -subject -issuer -dateopt iso_8601 -dates -ext), $exts);

  my $index = 0;
  for my $c (@certs) {
    my ($code, $out, $err) = run_with_input(\@run_cmd, $c);
    die "Error (index $index): $err\n" unless $code == 0;

    my $do_print = 0;
    if ($subject_grep_arg) {
      if ($out =~ m,^subject=.+?${subject_grep_arg},mi) {
        $do_print = 1;
      }
    } else {
      $do_print = 1;
    }

    if ($do_print) {
      print "index: $index\n";
      $out =~ s/\s*((?:DNS|IP Address):\S+)\s*/\n    ${1}/g;
      $out =~ s/\s+$//;
      print "$out\n\n";
    }

    $index++;
  }
}
