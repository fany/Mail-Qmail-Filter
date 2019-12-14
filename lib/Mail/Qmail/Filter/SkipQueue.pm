use 5.014;
use warnings;

package Mail::Qmail::Filter::SkipQueue;

our $VERSION = '1.0';

use Mo;
extends 'Mail::Qmail::Filter';

sub filter {
    my $self    = shift;
    my $message = $self->message;
    my @to      = $message->to;

    require Qmail::Deliverable and Qmail::Deliverable->import('dot_qmail')
      unless defined &dot_qmail;

    my $dot_qmail;
    for (@to) {
        my $_dot_qmail = dot_qmail($_)
          or return $self->debug( 'No .qmail file found for rcpt' => $_ );
        $self->debug( 'using file' => $_dot_qmail );
        return $self->debug('Delivery to different .qmail files not supported')
          if defined $dot_qmail && $_dot_qmail ne $dot_qmail;
        $dot_qmail = $_dot_qmail;
    }

    open my $fh, '<', $dot_qmail
      or return $self->debug( 'Cannot read $dot_qmail', $! );

    my @commands;
    while ( defined( my $line = <$fh> ) ) {
        next if /^#/;
        chomp $line;
        if ( $line !~ /^\|/ ) {
            $self->debug( 'Delivery method not supported', $line );
            return;
        }
        else {
            push @commands, $line;
        }
    }

    local $ENV{SENDER} = $message->from;
    for (@commands) {
        require Capture::Tiny and Capture::Tiny->import('capture_merged')
          unless defined &capture_merged;
        my ( $output, $exitcode ) = capture_merged(
            sub {
                open my $fh, $_ or return $self->debug( "Cannot start $_", $! );
                print $fh $message->body;
                close $fh;
                $?;
            }
        );
        $output = join '/', split /\n/, $output;
        $exitcode >>= 8;
        $self->debug( qq("$_" returned with exit code $exitcode) => $output );
        next                   if $exitcode == 0;
        last                   if $exitcode == 99;
        $self->reject($output) if $exitcode == 100;
        return;
    }

    $self->debug( action => 'delivered' );
    exit 0;
}

1;
