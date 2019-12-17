use 5.014;
use warnings;

package Mail::Qmail::Filter::CheckDelivery;

our $VERSION = '1.0';

use Mo qw(coerce);
extends 'Mail::Qmail::Filter';

has 'match';

sub filter {
    my $self    = shift;
    my $message = $self->message;
    my $match   = $self->match;

    require Qmail::Deliverable and Qmail::Deliverable->import('dot_qmail')
      unless defined &dot_qmail;

    my ( %done, $reject_text );
    for ( $message->to ) {
        my $dot_qmail = dot_qmail($_)
          or return $self->debug( 'No .qmail file found for rcpt' => $_ );
        next if $done{$dot_qmail}++;
        open my $fh, '<', $dot_qmail
          or return $self->debug( "Cannot read $dot_qmail", $! );
        $self->debug( "Checking .qmail for $_" => $dot_qmail );
        my $checked;
        while ( defined( my $line = <$fh> ) ) {
            chomp $line;
            return $self->debug( "$_ is at least deliverable to" => $line )
              if $line =~ m{^[&/\w]};
            next unless $line =~ /^\|/ and !defined $match || $line =~ $match;
            require Capture::Tiny
              and Capture::Tiny->import('capture_merged')
              unless defined &capture_merged;
            local $ENV{SENDER} = $message->from;
            my ( $output, $exitcode ) = capture_merged(
                sub {
                    open my $fh, $line
                      or return $self->debug( "Cannot start $line", $! );
                    print $fh $message->body;
                    close $fh;
                    $?;
                }
            );
            $output = join '/', split /\n/, $output;
            $exitcode >>= 8;
            $self->debug( qq("$line") => $exitcode );
            last if $exitcode == 99;
            if ( $exitcode == 100 ) {
                unless ( defined $reject_text ) {
                    $reject_text = $output;
                }
                elsif ( $output ne $reject_text ) {
                    return $self->debug(
                        qq(Different reject texts: "$reject_text" vs. "$output")
                    );
                }
            }
            elsif ( $exitcode == 111 ) {
                return $self->debug(
                    "Calling $line for $_ resulted in soft failure");
            }
            ++$checked;
        }
        return $self->debug( 'Could not check delivery for', $_ )
          unless $checked;
    }

    $self->reject($reject_text) if defined $reject_text;
}

1;
