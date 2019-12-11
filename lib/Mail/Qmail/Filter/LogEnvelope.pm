use 5.014;
use warnings;

package Mail::Qmail::Filter::LogEnvelope;

our $VERSION = '1.0';

use base 'Mail::Qmail::Filter';

use Carp qw(croak);

my $skip_if_relayclient;

use namespace::clean;

sub import {
    my $package = shift;
    $package->register;
    for (@_) {
        if ( $_ eq ':skip_if_relayclient' ) { $skip_if_relayclient = 1 }
        else {
            croak qw($package does not support feature $_);
        }
    }
}

sub run {
    my $filter = shift;

    $filter->debug( RELAYCLIENT => "$ENV{TCPREMOTEHOST} [$ENV{TCPREMOTEIP}]" )
      if exists $ENV{RELAYCLIENT};
    my $message = $filter->message;
    $filter->debug( 'RFC5321.MailFrom' => $message->from || '<>' );
    $filter->debug( to => join ', ', $message->to );
}

sub skip_if_relayclient {
    $skip_if_relayclient;
}

1;
