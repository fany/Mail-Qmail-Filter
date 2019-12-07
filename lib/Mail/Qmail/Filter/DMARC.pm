use 5.014;
use warnings;

package Mail::Qmail::Filter::DMARC;

our $VERSION = '1.0';

use Mail::DKIM::Verifier;
use Mail::DMARC::PurePerl;
use base 'Mail::Qmail::Filter';

sub domain {
    shift =~ s/.*\@//r;
}

sub if_set {
    my ( $key, $value ) = @_;
    return unless defined $value && length $value;
    $key => $value;
}

sub spf_query {
    require Mail::SPF;
    my $request = Mail::SPF::Request->new(@_);
    state $server = Mail::SPF::Server->new;
    $server->process($request);
}

use namespace::clean;

sub import {
    __PACKAGE__->register;
}

sub run {
    my $filter  = shift;
    my $message = $filter->message;

    my $envelope_from = $message->from;
    $filter->debug( 'RFC5321.MailFrom' => $envelope_from );
    $filter->debug( to => join ', ', $message->to );

    if ( exists $ENV{RELAYCLIENT} ) {
        $filter->debug(
            RELAYCLIENT => "$ENV{TCPREMOTEHOST} [$ENV{TCPREMOTEIP}]" );
    }
    else {

        my $dkim = Mail::DKIM::Verifier->new;
        $dkim->PRINT( $message->body =~ s/\cM?\cJ/\cM\cJ/gr );
        $dkim->CLOSE;
        $filter->debug( 'DKIM result' => $dkim->result );

        if ( $dkim->result ne 'pass' ) {

            $filter->debug( 'Remote IP' => $ENV{TCPREMOTEIP} );

            my %spf_query = ( ip_address => $ENV{TCPREMOTEIP} );

            $filter->debug( helo => $spf_query{helo_identity} =
                  $message->helo );

            my $header_from = $message->header_from;
            my $header_from_domain;
            if ($header_from) {
                $filter->debug( 'RFC5322.From' => $spf_query{identity} =
                      $header_from->address );
                $header_from_domain = $header_from->host;
                $spf_query{scope} = 'mfrom';
            }
            else {
                $spf_query{scope} = 'helo';

                # identity required by Mail::SPF:
                $spf_query{identity} = $spf_query{helo_identity};
            }

            $filter->debug( 'SPF result' => my $spf_result =
                  spf_query(%spf_query) );
            $message->add_header( $spf_result->received_spf_header );

            my $dmarc_text = (
                my $dmarc_result = Mail::DMARC::PurePerl->new(
                    source_ip   => $ENV{TCPREMOTEIP},
                    envelope_to => domain( ( $message->to )[0] ),
                    if_set( envelope_from => domain($envelope_from) ),
                    if_set( header_from   => $header_from_domain ),
                    dkim => $dkim,
                    spf  => {
                        if_set( domain => $header_from_domain ),
                        scope  => $spf_query{scope},
                        result => $spf_result->code,
                    },
                )->validate
            )->result;
            $filter->debug( 'DMARC result' => $dmarc_text );
            $message->add_header("DMARC-Status: $dmarc_text");

            if ( $dmarc_result->result ne 'pass' ) {
                my $disposition = $dmarc_result->disposition;
                $filter->debug( 'DMARC disposition' => $disposition );
                $filter->reject('Failed DMARC test.')
                  if $disposition eq 'reject' && $ENV{DMARC_REJECT};
            }
        }
    }
}

__END__

=head1 NAME

Mail::Qmail::Filter::DMARC - verify DMARC policy of mail message

=head1 SYNOPSIS

    use Mail::Qmail::Filter::DMARC;

    Mail::Qmail::Filter->run;

=head1 DESCRIPTION

This L<Mail::Qmail::Filter> plugin verifies if the incoming e-mail message
conforms to the DMARC policy of its sender domain:

=over 4

=item 1.

If the environment variable C<RELAYCLIENT> exists, no verification is done,
and the e-mail is immediately passed to C<qmail-queue>.

=item 2.

In any other case, we check if the message contains a valid DKIM signature
matching the domain of the C<From:> header field.
If this is the case, the e-mail is passed to C<qmail-queue>.

=item 3.

If not, a SPF check is done, and a C<Received-SPF:> header field is added to
the message.
Then we check if the message is aligned with its sender's DMARC policy.
A C<DMARC-Status:> header field is added.

If the message does not align to the policy, the policy advises to reject such
messages and when the environment variable C<DMARC_REJECT> is set to a true
value, the message will be rejected with C<554 Failed DMARC test.>

=item 4.

In any other case the message is passed on to C<qmail-queue>.

=back

Diagnostic messages are written as a single line to standard error,
so you should find them in your C<qmail-smtpd>'s log.

=head1 OPTIONS

Apart from controlling the rejection of messages via the environment variable
C<DMARC_REJECT>, none.
It just works the way I need it.
If you need it to operate in any other way, please let me know.
