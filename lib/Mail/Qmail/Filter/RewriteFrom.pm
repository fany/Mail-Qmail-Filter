use 5.014;
use warnings;

package Mail::Qmail::Filter::RewriteFrom;

our $VERSION = '1.0';

use Mo qw(coerce required);
extends 'Mail::Qmail::Filter';

has from => required => 1;

sub filter {
    my $self    = shift;
    my $message = $self->message;
    my $header  = $message->header;

    if ( my $from = $header->get('From') ) {
        chomp $from;
        if ( my $reply_to = $header->get('Reply-To') ) {
            chomp $reply_to;
            $self->debug( 'Reply-To already set', $reply_to );
        }
        else {
            $header->replace( 'Reply-To' => $from );
            $self->debug( 'set Reply-To to From', $from );
        }
        $header->replace( From => $self->from );
        $self->debug( 'set RFC5322.From', $self->from );
        $message->replace_header($header);
    }
}

1;
