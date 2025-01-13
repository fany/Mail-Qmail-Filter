use 5.02;        # because we use ->%*
use warnings;    # no default before Perl 5.35

package Mail::Qmail::Filter::VerifySender;

our $VERSION = '0.31';

use Mo qw(coerce default);
extends 'Mail::Qmail::Filter';

has 'dump_rejected_to';
has net_dns_resolver_params => {};
has net_smtp_params         => { Hello => undef, Timeout => 10 };

sub filter {
    my $self = shift;
    length( my $mail_from = $self->message->from ) or return;
    $self->debug("Verifying sender address <$mail_from>");

    my ($domain) = $mail_from =~ /\@(.*)/;

    require Net::DNS::Resolver;
    state $resolver =
      Net::DNS::Resolver->new( $self->net_dns_resolver_params->%* );
    my $packet = $resolver->send( $domain, 'MX' );
    $self->defer( "Error resolving MX for $domain " . $packet->header->rcode )
      if $packet->header->rcode ne 'NOERROR';
    my @mx = map $_->exchange,
      sort { $a->preference <=> $b->preference } grep $_->type eq 'MX',
      $packet->answer;

    if (@mx) {
        $self->debug("MXes for sender domain $domain: @mx");
    }
    else {
        @mx = $domain;
        $self->debug("Sender domain $domain has no MX; fallback to A RR.");
    }
    $self->reject("Domain $domain of sender has no valid MX.") unless @mx;

    require Net::SMTP;
    my %net_smtp_params = $self->net_smtp_params->%*;
    if ( exists $net_smtp_params{Hello}
        && !defined $net_smtp_params{Hello} )
    {
        require Net::Domain and Net::Domain->import('hostfqdn')
          unless defined &hostfqdn;
        $net_smtp_params{Hello} = hostfqdn();
    }
    if ( my $smtp = Net::SMTP->new( Host => \@mx, %net_smtp_params ) ) {
        $smtp->starttls;
        $smtp->mail('<>');
        $smtp->recipient($mail_from);
        my $code = $smtp->code;
        chomp( my $message = $smtp->message );
        $smtp->quit;
        $self->debug( $smtp->host . " returned $code $message" );
        return if $code != 550;

        if ( defined( my $dir = $self->dump_rejected_to ) ) {
            require Path::Tiny and Path::Tiny->import('path')
              unless defined &path;
            path( $dir, my $file = join '_', $^T, $$ )
              ->spew( $self->message->body );
            $self->debug( 'dumped message to' => $file );
        }
        $self->reject( 'According to '
              . $smtp->host
              . ", <$mail_from> isn't a valid e-mail address: $code $message" );
    }
    else {
        $self->debug( "Could not connect to " . $smtp->host . ": $!" );
    }
    $self->debug('Could not verify sender address.');
    return;
}

1;

__END__

=head1 NAME

Mail::Qmail::Filter::VerifySender -
check syntax of RFC5321.MailFrom address

=head1 SYNOPSIS

    use Mail::Qmail::Filter;

    Mail::Qmail::Filter->new->add_filters(
        '::VerifySender' => {
            skip_for_rcpt => [ 'postmaster', 'postmaster@' . $mydomain ],
        },
        '::Queue',
    )->run;

=head1 DESCRIPTION

This L<Mail::Qmail::Filter> plugin checks if the RFC5321.MailFrom aka the
envelope sender of the message is an existing e-mail address via doing
SMTP callouts.

The sender is rejected in any of the following constellations:

=over 4

=item *

There is no valid MX or A RR for the sender domain.

=item *

An authorititative MX can be reached and returns error code 550 when
trying to send an e-mail to the sender address.

=back

In any other cases (such as timeouts or other errors), we do not reject
the e-mail.

=head1 OPTIONAL PARAMETERS

=head2 net_dns_resolver_params

reference to a hash of parameters to pass when creating the
L<Net::DNS::Resolver> object to resolve sender domains

Default: C<{}>

=head2 net_smtp_params

reference to a hash of parameters to pass to L<Net::SMTP>->new
when creating SMTP connections

Default: C<{ Hello =E<gt> undef, Timeout =E<gt> 5 }>

Special case: An L<undef|perlfunc/undef>ined value for C<Hello> causes
this module to set that parameter by calling L<Net::Domain/hostfqdn()>.

=head2 dump_spam_to

If the message is rejected, copy it into a file in the given directory.
The file will be named 
C<E<lt>epoch_time_when_script_startedE<gt>_E<lt>pidE<gt>

=head1 SEE ALSO

L<Mail::Qmail::Filter/COMMON PARAMETERS FOR ALL FILTERS>

=head1 LICENSE AND COPYRIGHT

Copyright 2025 Martin Sluka.

This module is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=cut
