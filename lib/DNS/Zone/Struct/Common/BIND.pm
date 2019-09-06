package DNS::Zone::Struct::Common::BIND;

# DATE
# VERSION

use 5.010001;
use strict;
use warnings;
use Log::ger;

use Exporter 'import';
our @EXPORT_OK = qw(
               );

our %arg_workaround_root_cname = (
    workaround_root_cname => {
        summary => "Whether to avoid having CNAME record for a name as well as other record types",
        description => <<'_',

CNAME on a root node (host='') does not make sense, so the workaround is to
ignore the root CNAME.

_
        schema => 'bool*',
        default => 1,
        tags => ['category:workaround'],
    },
);

our %arg_workaround_cname_and_other_data = (
    workaround_cname_and_other_data => {
        summary => "Whether to avoid having CNAME record for a name as well as other record types",
        description => <<'_',

This is a workaround for a common misconfiguration. Bind will reject the whole
zone if there is CNAME record for a name (e.g. 'www') as well as other record
types (e.g. 'A' or 'TXT'). The workaround is to skip those A/TXT records and
only keep the CNAME record.

_
        schema => 'bool*',
        default => 1,
        tags => ['category:workaround'],
    },
);

sub _workaround_cname_and_other_data {
}
our %arg_workaround_no_ns = (
    workaround_no_ns => {
        summary => "Whether to add some NS records for '' when there are no NS records for it",
        description => <<'_',

This is a workaround for a common misconfiguration in PowerDNS DB. This will add
some NS records specified in `default_ns`.

_
        schema => 'bool*',
        default => 1,
        tags => ['category:workaround'],
    },
    default_ns => {
        schema => ['array*', of=>'net::hostname*'],
    },
);


# XXX
sub _encode_txt {
    my $text = shift;
    qq("$text");
}

$SPEC{gen_bind_zone_from_powerdns_db} = {
    v => 1.1,
    summary => 'Generate BIND zone configuration from '.
        'information in PowerDNS database',
    args => {
        dbh => {
            schema => 'obj*',
        },
        db_dsn => {
            schema => 'str*',
            tags => ['category:database'],
            default => 'DBI:mysql:database=pdns',
        },
        db_user => {
            schema => 'str*',
            tags => ['category:database'],
        },
        db_password => {
            schema => 'str*',
            tags => ['category:database'],
        },
        domain => {
            schema => ['net::hostname*'], # XXX domainname
            pos => 0,
        },
        domain_id => {
            schema => ['uint*'], # XXX domainname
        },
        workaround_no_ns => {
            summary => "Whether to add some NS records for '' when there are no NS records for it",
            description => <<'_',

This is a workaround for a common misconfiguration in PowerDNS DB. This will add
some NS records specified in `default_ns`.

_
            schema => 'bool*',
            default => 1,
            tags => ['category:workaround'],
        },
        workaround_root_cname => {
            summary => "Whether to avoid having CNAME record for a name as well as other record types",
            description => <<'_',

CNAME on a root node (host='') does not make sense, so the workaround is to
ignore the root CNAME.

_
            schema => 'bool*',
            default => 1,
            tags => ['category:workaround'],
        },
        workaround_cname_and_other_data => {
            summary => "Whether to avoid having CNAME record for a name as well as other record types",
            description => <<'_',

This is a workaround for a common misconfiguration in PowerDNS DB. Bind will
reject the whole zone if there is CNAME record for a name (e.g. 'www') as well
as other record types (e.g. 'A' or 'TXT'). The workaround is to skip those A/TXT
records and only keep the CNAME record.

_
            schema => 'bool*',
            default => 1,
            tags => ['category:workaround'],
        },
        default_ns => {
            schema => ['array*', of=>'net::hostname*'],
        },
    },
    args_rels => {
        req_one => ['domain', 'domain_id'],
    },
    result_naked => 1,
};
sub gen_bind_zone_from_powerdns_db {
    my %args = @_;
    my $domain = $args{domain};

    my $dbh;
    if ($args{dbh}) {
        $dbh = $args{dbh};
    } else {
        require DBIx::Connect::Any;
        $dbh = DBIx::Connect::Any->connect(
            $args{db_dsn}, $args{db_user}, $args{db_password}, {RaiseError=>1});
    }

    my $sth_sel_domain;
    if (defined $args{domain_id}) {
        $sth_sel_domain = $dbh->prepare("SELECT * FROM domains WHERE id=?");
        $sth_sel_domain->execute($args{domain_id});
    } else {
        $sth_sel_domain = $dbh->prepare("SELECT * FROM domains WHERE name=?");
        $sth_sel_domain->execute($domain);
    }
    my $domain_rec = $sth_sel_domain->fetchrow_hashref
        or die "No such domain in the database: '$domain'";
    $domain //= $domain_rec->{name};

    my @res;
    push @res, '; generated from PowerDNS database on '.scalar(gmtime)." UTC\n";

    my $soa_rec;
  GET_SOA_RECORD: {
        my $sth_sel_soa_record = $dbh->prepare("SELECT * FROM records WHERE domain_id=? AND disabled=0 AND type='SOA'");
        $sth_sel_soa_record->execute($domain_rec->{id});
        $soa_rec = $sth_sel_soa_record->fetchrow_hashref
            or die "Domain '$domain' does not have SOA record";
        push @res, '$TTL ', $soa_rec->{ttl}, "\n";
        $soa_rec->{content} =~ s/(\S+)(\s+)(\S+)(\s+)(.+)/$1.$2$3.$4($5)/;
        push @res, "\@ IN $soa_rec->{ttl} SOA $soa_rec->{content};\n";
    }

    my @recs;
  GET_RECORDS:
    {
        my $sth_sel_record = $dbh->prepare("SELECT * FROM records WHERE domain_id=? AND disabled=0 ORDER BY id");
        $sth_sel_record->execute($domain_rec->{id});
        while (my $rec = $sth_sel_record->fetchrow_hashref) {
            $rec->{name} =~ s/\.?\Q$domain\E\z//;
            push @recs, $rec;
        }
    }

  WORKAROUND_NO_NS:
    {
        # when there are no NS records for host '', bind will complain and
        # reject the zone. we add default_ns in that case.
        last unless $args{workaround_no_ns} // 1;

        my $has_ns_record_for_domain;
        for (@recs) {
            if ($_->{type} eq 'NS' && $_->{name} eq '') { $has_ns_record_for_domain++; last }
        }

        last if $has_ns_record_for_domain;

        die "Please specify one or more default NS (`default_ns`) for --workaround-no-ns"
            unless $args{default_ns} && @{ $args{default_ns} };
        log_warn "There are no NS records for host '', assuming misconfiguration, adding workaround: some default NS: %s", $args{default_ns};
        for my $ns (@{ $args{default_ns} }) {
            push @recs, {type=>'NS', name=>'', content=>$ns};
        }
    }

  WORKAROUND_ROOT_CNAME:
    {
        # CNAME does not make sense for a root node (name=''), so the workaround
        # is to ignore this record.
        last unless $args{workaround_root_cname} // 1;

        my @recs0 = @recs;
        @recs = ();
        for (@recs0) {
            if ($_->{type} eq 'CNAME' && $_->{name} eq '') {
                log_warn "There is a CNAME record for host '', assuming misconfiguration, adding workaround: skipping this CNAME record (%s)", $_;
                next;
            }
            push @recs, $_;
        }

    }

  WORKAROUND_CNAME_AND_OTHER_DATA:
    {
        # for the same host, if there's a CNAME record there should not be any
        # other types of record. if there are, we add a workaround and ignore
        # those records and choose CNAME instead. this is often a mistake made
        # when configuring google apps domains.
        last unless $args{workaround_cname_and_other_data} // 1;

        my %cname_for; # key=host(name)
        for (@recs) {
            next unless $_->{type} eq 'CNAME';
            $cname_for{ $_->{name} }++;
        }

        my @recs0 = @recs;
        @recs = ();
        for (@recs0) {
            goto PASS if $_->{type} eq 'CNAME';
            if ($cname_for{ $_->{name} }) {
                log_warn "There is a CNAME for name=%s as well as %s record, assuming misconfiguration, adding workaround: skipping the %s record (%s)",
                    $_->{name}, $_->{type}, $_->{type}, $_;
                next;
            }
          PASS:
            push @recs, $_;
        }
    }

  SORT_RECORDS:
    {
        # bind requires some particular ordering of records...
        @recs = sort {
            my $cmp;

            # root node firsts
            my $a_is_root = $a->{name} eq '' ? 0 : 1;
            my $b_is_root = $b->{name} eq '' ? 0 : 1;
            return $cmp if $cmp = $a_is_root <=> $b_is_root;

            # we need to sort wildcard records RIGHT above non-wildcard records;
            # otherwise we might get, e.g. 'CNAME and other data' error, where
            # there is '* A' or '* MX', followed by 'www CNAME' which will be
            # rejected by bind because www gets CNAME as well as A or MX, while
            # CNAME cannot be mixed with other record types.
            my $a_cname_and_wildcard_score = $a->{type} eq 'CNAME' ? 1 : $a->{name} =~ /\*/ ? 2 : 3;
            my $b_cname_and_wildcard_score = $b->{type} eq 'CNAME' ? 1 : $b->{name} =~ /\*/ ? 2 : 3;
            return $cmp if $cmp = $a_cname_and_wildcard_score <=> $b_cname_and_wildcard_score;

            $a->{name} cmp $b->{name};
        } @recs;
    }

    for my $rec (@recs) {
        my $type = $rec->{type};
        next if $type eq 'SOA';
        my $name = $rec->{name};
        push @res, "$name ", ($rec->{ttl} ? "$rec->{ttl} ":""), "IN ";
        if ($type eq 'A') {
            push @res, "A $rec->{content}\n";
        } elsif ($type eq 'CNAME') {
            push @res, "CNAME $rec->{content}.\n";
        } elsif ($type eq 'MX') {
            push @res, "MX $rec->{prio} $rec->{content}.\n";
        } elsif ($type eq 'NS') {
            push @res, "NS $rec->{content}.\n";
        } elsif ($type eq 'SSHFP') {
            push @res, "SSHFP $rec->{content}\n";
        } elsif ($type eq 'SRV') {
            push @res, "SRV $rec->{prio} $rec->{content}\n";
        } elsif ($type eq 'TXT') {
            push @res, "TXT ", _encode_txt($rec->{content}), "\n";
        } else {
            die "Can't dump record with type $type";
        }
    }

    join "", @res;
}

1;
# ABSTRACT: BIND-related DNS zone routines

=head1 SYNOPSIS


=head1 SEE ALSO

L<DNS::Zone::Struct::To::BIND>

L<DNS::Zone::PowerDNS::To::BIND>
