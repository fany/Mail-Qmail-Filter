use 5.014;
use warnings;

package Mail::Qmail::Filter::LogEnvelope;

our $VERSION = '2.0';

use Mo qw(coerce);
extends 'Mail::Qmail::Filter';

sub filter {
    my $self = shift;

    $self->debug(
        RELAYCLIENT => ( defined $ENV{TCPREMOTEHOST} && "$ENV{TCPREMOTEHOST} " )
          . "[$ENV{TCPREMOTEIP}]" )
      if exists $ENV{RELAYCLIENT};
    my $message = $self->message;
    $self->debug( 'RFC5321.MailFrom' => $message->from || '<>' );
    $self->debug( to => join ', ', $message->to );
}

1;
