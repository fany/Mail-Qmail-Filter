use 5.014;
use warnings;

package Mail::Qmail::Filter::ValidateFrom;

our $VERSION = '1.0';

use Mo qw(coerce default);
extends 'Mail::Qmail::Filter';

has 'params'      => {};
has 'reject_text' => 'Invalid address in From header line.';

sub filter {
    my $self                = shift;
    my $header_from         = $self->message->header_from or return;
    my $header_from_address = $header_from->address;

    require Email::Valid;
    $self->reject( $self->reject_text, $header_from_address )
      unless Email::Valid->new( %{ $self->params } )
      ->address($header_from_address);
}

1;
