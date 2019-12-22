use 5.014;
use warnings;

package Mail::Qmail::Filter::RequireFrom;

our $VERSION = '1.0';

use Mail::Qmail::Filter::Util qw(addresses2hash match_addr);

use namespace::clean;

use Mo qw(coerce default required);
extends 'Mail::Qmail::Filter';

has 'allowed_addresses' => coerce => \&addresses2hash, required => 1;
has 'lowercase_from';
has 'reject_text' => sub { "<@_> not allowed as RFC5322.From" };

sub filter {
    my $self                = shift;
    my $header_from_address = '';
    if ( my $header_from = $self->message->header_from ) {
        $header_from_address = $header_from->address;
        return
          if match_addr( $self->allowed_addresses,
            $self->lowercase_from
            ? lc $header_from_address
            : $header_from_address );
    }
    $self->reject( $self->reject_text, $header_from_address );
}

1;
