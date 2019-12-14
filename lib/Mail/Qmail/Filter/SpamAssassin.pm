use 5.014;
use warnings;

package Mail::Qmail::Filter::SpamAssassin;

our $VERSION = '1.1';

sub normalize_addr {
    my ( $localpart, $domain ) = split /\@/, shift, 2;
    "$localpart\@\L$domain";
}

use namespace::clean;

use Mo qw(coerce default);
extends 'Mail::Qmail::Filter';

has 'dump_spam_to';
has 'mark';
has 'reject_score';
has 'reject_text' => 'I think this message is spam.';
has 'skip_for_rcpt' => coerce => sub {
    my $addrs = shift;
    $addrs = [$addrs] unless ref $addrs;
    my %skip_for_rcpt;
    $skip_for_rcpt{ normalize_addr($_) } = undef
      for ref $addrs ? @$addrs : $addrs;
    \%skip_for_rcpt;
};

sub run {
    my $self    = shift;
    my $message = $self->message;
    {
        my $skip_for_rcpt = $self->skip_for_rcpt;
        if ( keys %$skip_for_rcpt ) {
            for ( $message->to ) {
                next unless exists $skip_for_rcpt->{ normalize_addr $_};
                $self->debug( 'skipped because of rcpt', $_ );
                return;
            }
        }
    }
    my $body_ref = $message->body_ref;

    require Mail::SpamAssassin;    # lazy load because filter might be skipped
    my $sa     = Mail::SpamAssassin->new;
    my $mail   = $sa->parse($body_ref);
    my $status = $sa->check($mail);
    $self->debug( 'spam score' => my $score = $status->get_score );

    if ( $status->is_spam ) {
        if ( defined( my $dir = $self->dump_spam_to ) ) {
            require Path::Tiny and Path::Tiny->import('path')
              unless defined &path;
            path( $dir, my $file = join '_', $^T, $$, $score )
              ->spew($$body_ref);
            $self->debug( 'dumped message to' => $file );
            path( $dir, $file . '_report' )->spew( $status->get_report );
        }
        $self->reject( $self->reject_text =~ y/\n/ /r )
          if $self->reject_score && $score >= $self->reject_score;
        $$body_ref = $status->rewrite_mail if $self->mark;
    }
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
