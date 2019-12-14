use 5.014;
use warnings;

package Mail::Qmail::Filter::LogEnvelope;

our $VERSION = '1.0';

use Mo;
extends 'Mail::Qmail::Filter';

use Carp qw(croak);

use namespace::clean;

sub run {
    my $self = shift;

    $self->debug( RELAYCLIENT => "$ENV{TCPREMOTEHOST} [$ENV{TCPREMOTEIP}]" )
      if exists $ENV{RELAYCLIENT};
    my $message = $self->message;
    $self->debug( 'RFC5321.MailFrom' => $message->from || '<>' );
    $self->debug( to => join ', ', $message->to );
}

1;
