use 5.014;
use warnings;

package Mail::Qmail::Filter;

our $VERSION = '2.0';

use IO::Handle;
use MailX::Qmail::Queue::Message;
use Mo qw(default);

my $feedback_fh;

BEGIN {
    # Open ASAP before the handle gets reused:
    $feedback_fh = IO::Handle->new_from_fd( 4, 'w' )
      or warn "Cannot open feedback handle: $!";
}

use Carp qw(confess);
use FindBin ();

use namespace::clean;

has 'filters' => [];
has 'skip_if_relayclient';

my @debug;

sub debug {
    my $self = shift;
    push @debug, join ': ', @_;
}

$SIG{__DIE__} //= sub {
    __PACKAGE__->debug( died => "@_" ) unless $^S;
    die @_;
};

sub add_filter {
    my ( $self, $type, @opt ) = @_;
    $type = __PACKAGE__ . "::$type" if $type !~ /::/;
    eval "use $type";
    confess $@ if length $@;
    push @{ $self->{filters} }, $type->new(@opt);
    $self;
}

sub filter {
    my $self = shift;

    $_->run for @{ $self->filters };

    delete $ENV{QMAILQUEUE};    # use original qmail-queue
    $self->message->send == 0 or die "Error sending message: exit status $?\n";
    $self->debug( action => 'queue' );
}

sub reject {
    my $self = shift;
    $feedback_fh->print("D@_");
    $self->debug( action => 'reject' );
    exit 88;
}

sub message {
    state $message = MailX::Qmail::Queue::Message->receive
      or die "Invalid message\n";
}

sub run {
    my $self = shift;

    my $package = ref $self;
    if ( exists $ENV{RELAYCLIENT} && $self->skip_if_relayclient ) {
        $self->debug("$package skipped");
    }
    else {
        $self->debug("$package started");
        $self->filter;
    }
}

END {
    __PACKAGE__->debug( 'exit code' => $? );
    say STDERR "$FindBin::Script\[$$]: " . join '; ', @debug;
}

__END__

=head1 NAME

Mail::Qmail::Filter - filter e-mails in qmail-queue context

=head1 SYNOPSIS

    use Mail::Qmail::Filter::LogEnvelope;
    use Mail::Qmail::Filter::DMARC        qw(:skip_if_relayclient);
    use Mail::Qmail::Filter::SpamAssassin qw(:skip_if_relayclient :mark);

    Mail::Qmail::Filter->run;

=head1 DESCRIPTION

Mail::Qmail::Filter is designed to be called by qmail-smtpd instead of
qmail-queue via a simple frontend script like in the synopsis.

=head1 METHODS

=head2 ->run

Read the message from C<qmail-smtpd>,
run the filters which were loaded
and forward the message to C<qmail-queue>
if it is not rejected by one of the filters.

=head2 ->register

Register a filter plugin module to be run by the L</-E<gt>run> method.
Is usually called by the C<-E<gt>init> method of the filter plugin.

=head2 ->is_relayclient

Returns a true value only if the script is being called by a RELAYCLIENT,
that is, if the environment variable RELAYCLIENT is defined.
