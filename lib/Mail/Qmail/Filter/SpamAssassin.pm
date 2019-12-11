use 5.014;
use warnings;

package Mail::Qmail::Filter::SpamAssassin;

our $VERSION = '1.1';

use base 'Mail::Qmail::Filter';

use Carp qw(croak);

sub normalize_addr {
    my ( $localpart, $domain ) = split /\@/, shift, 2;
    "$localpart\@\L$domain";
}

my ( $mark, $reject, %skip_for_rcpt, $skip_if_relayclient );

use namespace::clean;

sub import {
    my $package = shift;
    $package->register;
    for (@_) {
        if    ( $_ eq ':mark' )                { $mark                = 1 }
        elsif ( $_ eq ':reject' )              { $reject              = 1 }
        elsif ( $_ eq ':skip_if_relayclient' ) { $skip_if_relayclient = 1 }
        else {
            croak qw($package does not support feature $_);
        }
    }
}

sub dump_spam_to {
    my $filter = shift;
    state $dump_spam_to;
    $dump_spam_to = shift if @_;
    $dump_spam_to;
}

sub reply_text {
    my $filter = shift;
    state $reply_text = 'I think this message is spam.';
    $reply_text = shift =~ y/\n/ /r if @_;
    $reply_text;
}

sub run {
    my $filter  = shift;
    my $message = $filter->message;

    if ( keys %skip_for_rcpt ) {
        for ( $message->to ) {
            next unless exists $skip_for_rcpt{ normalize_addr $_};
            $filter->debug( 'skipped because of rcpt', $_ );
            return;
        }
    }

    my $body_ref = $message->body_ref;

    require Mail::SpamAssassin;    # lazy load because filter might be skipped
    my $sa     = Mail::SpamAssassin->new;
    my $mail   = $sa->parse($body_ref);
    my $status = $sa->check($mail);
    $filter->debug( 'spam score' => $status->get_score );

    if ( $status->is_spam ) {
        if ( defined( my $dir = $filter->dump_spam_to ) ) {
            require Path::Tiny and Path::Tiny->import('path')
              unless defined &path;
            path( $dir, my $file = "$^T.$$" )->spew($$body_ref);
            $filter->debug( 'dumped message to' => $file );
        }
        $filter->reject( $filter->reply_text ) if $reject;
        $$body_ref = $status->rewrite_mail if $mark;
    }
}

sub skip_for_rcpt {
    my $filter = shift;
    @skip_for_rcpt{ map normalize_addr($_), @_ } = ();
}

sub skip_if_relayclient {
    $skip_if_relayclient;
}

1;

__END__

=head1 NAME

Mail::Qmail::Filter::SpamAssassin - check if mail message is spam

=head1 SYNOPSIS

    use Mail::Qmail::Filter::SpamAssassin qw(:mark :skip_if_relayclient);

    Mail::Qmail::Filter->run;

=head1 DESCRIPTION

This L<Mail::Qmail::Filter> plugin checks if the incoming e-mail message
is probably spam.

If imported with the C<:skip_if_relayclient> feature, the plugin is skipped
if the message comes from a relay client.

If imported with the C<:reject> feature, it will reject suspicious
messages.

Otherwise, if imported with the C<:mark> feature, messages will be marked
as described in L<Mail::SpamAssassin::PerMsgStatus>.

Otherwise, the spam score is just logged.
