use 5.014;
use warnings;

package Mail::Qmail::Filter::SpamAssassin;

our $VERSION = '1.0';

use base 'Mail::Qmail::Filter';

use Carp qw(croak);
use Mail::SpamAssassin;

my ( $mark, $reject );

use namespace::clean;

sub import {
    my $package = shift;
    $package->register;
    for (@_) {
        if    ( $_ eq ':mark' )   { $mark   = 1 }
        elsif ( $_ eq ':reject' ) { $reject = 1 }
        else {
            croak qw($package does not support feature $_);
        }
    }
}

sub run {
    my $filter   = shift;
    my $message  = $filter->message;
    my $body_ref = $message->body_ref;
    my $sa       = Mail::SpamAssassin->new;
    my $mail     = $sa->parse($body_ref);
    my $status   = $sa->check($mail);
    $filter->debug( 'spam score' => $status->get_score );
    if ( $status->is_spam ) {
        $filter->reject('I think this message is spam.') if $reject;
        $$body_ref = $status->rewrite_mail if $mark;
    }
}

1;

__END__

=head1 NAME

Mail::Qmail::Filter::SpamAssassin - check if mail message is spam

=head1 SYNOPSIS

    use Mail::Qmail::Filter::SpamAssassin qw(:mark);

    Mail::Qmail::Filter->run;

=head1 DESCRIPTION

This L<Mail::Qmail::Filter> plugin checks if the incoming e-mail message
is probably spam.

If imported with the C<:reject> feature, it will reject suspicious
messages.

Otherwise, if imported with the C<:mark> feature, messages will be marked
as described in L<Mail::SpamAssassin::PerMsgStatus>.

Otherwise, the spam score is just logged.
