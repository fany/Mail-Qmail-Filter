use 5.014;
use warnings;

package Mail::Qmail::Filter::Dump;

our $VERSION = '2.0';

use Mo qw(coerce required);
extends 'Mail::Qmail::Filter';

has 'to' => required => 1;

sub filter {
    my $self    = shift;
    my $message = $self->message;
    require Path::Tiny and Path::Tiny->import('path')
      unless defined &path;
    my $dest = path( $self->to );
    state $i = 0;
    $dest = $dest->child( join '_', $^T, $$, ++$i ) if $dest->is_dir;
    $dest->spew( $message->body );
    $self->debug( 'dumped message to' => $dest );
}

1;
