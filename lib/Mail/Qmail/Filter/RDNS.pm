use 5.014;
use warnings;

package Mail::Qmail::Filter::RDNS;

our $VERSION = '0.12';

use Mo qw(coerce default);
extends 'Mail::Qmail::Filter';

use Socket qw(
  AF_INET
  AF_INET6
  getaddrinfo
  getnameinfo
  inet_pton
  NI_NUMERICHOST
  SOCK_STREAM
);

sub filter {
    my $self = shift;

    my $remote_ip = $self->message->remote_ip
      or $self->debug('No remote IP!?'), return;
    my $addr_family = $remote_ip =~ /:/ ? AF_INET6 : AF_INET;
    my $packed_ip   = inet_pton( $addr_family, $remote_ip )
      or $self->debug("Cannot pack remote IP $remote_ip!?"), return;
    my $fqdn = gethostbyaddr( $packed_ip, $addr_family )
      or $self->reject("Your IP address $remote_ip has no reverse DNS entry.");

    $self->debug("$remote_ip resolved to $fqdn");
    my ( $err, @addresses ) =
      getaddrinfo( $fqdn, undef, { socktype => SOCK_STREAM } );
    $self->defer("$err resolving $fqdn")
      if $err && $err ne 'Name or service now known';
    for (@addresses) {
        next if $_->{family} != $addr_family;
        my ( $err, $ip ) = getnameinfo( $_->{addr}, NI_NUMERICHOST );
        return if inet_pton( $addr_family, $ip ) eq $packed_ip;
        $self->debug("$ip does not match");
    }
    $self->reject(
            "The reverse lookup of your IP address $remote_ip points to"
          . " $fqdn, but there is no matching DNS entry for this name." );
}

1;

__END__

=head1 NAME

Mail::Qmail::Filter::RDNS -
verify DNS reverse lookup of client

=head1 SYNOPSIS

    use Mail::Qmail::Filter;

    Mail::Qmail::Filter->new->add_filters(
        '::RDNS' => {
            skip_for_rcpt => [ 'postmaster', 'postmaster@' . $mydomain ],
        },
        '::Queue',
    )->run;

=head1 DESCRIPTION

This L<Mail::Qmail::Filter> plugin checks if there is a reverse DNS entry
for the IP address of the client and if there is a matching DNS entry for
the name it points to back to the IP address of the client.

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
