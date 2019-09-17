package DNS::Zone::Struct::Common;

# DATE
# VERSION

use 5.010001;
use strict;
use warnings;
use Log::ger;

our %arg_workaround_convert_underscore_in_host = (
    workaround_underscore_in_host => {
        summary => "Whether to convert underscores in hostname to dashes",
        description => <<'_',

Underscore is not a valid character in hostname. This workaround can help a bit
by automatically converting underscores to dashes. Note that it does not ensure
hostnames like `foo_.example.com` to become valid as `foo-.example.com` is also
not a valid hostname.

_
        schema => 'bool*',
        default => 1,
        tags => ['category:workaround'],
    },
);

sub _workaround_convert_underscore_in_host {
    my $recs = shift;

    for (@$recs) {
        if ($_->{host}) {
            my $orig_host = $_->{host};
            if ($_->{host} =~ s/_/-/g) {
                log_warn "There is a host containing underscore '$orig_host'; converting the underscores to dashes";
            }
        }
    }
}

1;
# ABSTRACT: Common routines related to DNS zone structure
