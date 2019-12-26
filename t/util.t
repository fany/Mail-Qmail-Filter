#!perl -T

use 5.014;
use warnings;
use Test::More tests => 3;

BEGIN {
    use_ok( 'Mail::Qmail::Filter::Util', qw(addresses_to_hash match_address) );
}

is_deeply addresses_to_hash('Martin@Sluka.DE'),
  { 'sluka.de' => { Martin => '' } }, 'single address';
is_deeply addresses_to_hash(
    [qw(Martin@Sluka.DE fany@checkts.net checkts.net)] ),
  { 'checkts.net' => '', 'sluka.de' => { Martin => '' } },
  'mixed list';
