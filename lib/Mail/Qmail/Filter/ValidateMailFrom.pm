use 5.014;
use warnings;

package Mail::Qmail::Filter::ValidateMailFrom;

our $VERSION = '1.0';

use Mo qw(coerce default);
extends 'Mail::Qmail::Filter';

has 'params'      => {};
has 'reject_text' => 'Invalid sender address.';

sub filter {
    my $self = shift;
    length( my $mail_from = $self->message->from ) or return;

    require Email::Valid;
    $self->reject( $self->reject_text, $mail_from )
      unless Email::Valid->new( %{ $self->params } )->address($mail_from);
}

1;
