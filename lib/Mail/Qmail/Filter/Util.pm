use 5.014;
use warnings;

package Mail::Qmail::Filter::Util;

our $VERSION = '1.0';

use base 'Exporter';

our @EXPORT_OK = qw(addresses2hash match_addr);

sub addresses2hash {
    my $addrs = shift;
    $addrs = [$addrs] unless ref $addrs;
    my %struct;
    for ( ref $addrs ? @$addrs : $addrs ) {
        my ( $localpart, $domain ) = split_addr($_);
        unless ( length $localpart ) {
            $struct{$domain} = '';    # match for whole domain
        }
        else {
            my $slot = $struct{$domain} //= {};
            $slot->{$localpart} = '' if ref $slot;
        }
    }
    \%struct;
}

sub match_addr {
    my ( $struct,    $addr )   = @_;
    my ( $localpart, $domain ) = split_addr($addr);
    defined( my $slot = $struct->{$domain} ) or return;
    !ref $slot || !length $localpart || defined $slot->{$localpart};
}

sub split_addr {
    my $addr = shift;
    if ( $addr =~ /\@/ ) {
        my ( $localpart, $domain ) = split /\@/, $addr, 2;
        $localpart, lc $domain;
    }
    else {
        undef, lc $addr;
    }
}

1;
