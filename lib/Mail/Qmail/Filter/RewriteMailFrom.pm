use 5.014;
use warnings;

package Mail::Qmail::Filter::RewriteMailFrom;

our $VERSION = '1.0';

use Mo qw(coerce required);
extends 'Mail::Qmail::Filter';

has mail_from => required => 1;

sub filter {
    my $self    = shift;
    my $message = $self->message;

    $self->debug( 'new RFC5321.MailFrom' => ${ $message->from_ref } =
          $self->mail_from );
}

1;
