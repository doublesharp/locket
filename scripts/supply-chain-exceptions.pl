#!/usr/bin/env perl
use strict;
use warnings;
use JSON::PP qw(decode_json);
use POSIX qw(strftime);
use Time::Local qw(timegm);

my ($ledger_path, $report_path) = @ARGV;
die "usage: supply-chain-exceptions.pl <ledger.json> <report.md>\n"
  unless defined $report_path;

my $today = $ENV{LOCKET_TODAY} // strftime('%Y-%m-%d', gmtime);
my $ledger = read_json($ledger_path);
my $exceptions = $ledger->{exceptions};
die "supply-chain exception ledger must contain an exceptions array\n"
  unless ref($exceptions) eq 'ARRAY';

my @rows;
my @errors;
my $index = 0;

for my $entry (@{$exceptions}) {
    ++$index;
    if (ref($entry) ne 'HASH') {
        push @errors, "exception $index must be an object";
        next;
    }

    my @entry_errors;
    for my $field (qw(package version reason owner expires_at)) {
        push @entry_errors, "$field is required"
          unless non_empty_string($entry->{$field});
    }

    if (ref($entry->{compensating_controls}) ne 'ARRAY'
        || !@{ $entry->{compensating_controls} }) {
        push @entry_errors, "compensating_controls must be a non-empty array";
    } else {
        for my $control (@{ $entry->{compensating_controls} }) {
            push @entry_errors, "compensating_controls entries must be non-empty strings"
              unless non_empty_string($control);
        }
    }

    if (non_empty_string($entry->{expires_at})) {
        if (!valid_ymd($entry->{expires_at})) {
            push @entry_errors, "expires_at must be YYYY-MM-DD";
        } elsif ($entry->{expires_at} lt $today) {
            push @entry_errors, "expires_at is before $today";
        }
    }

    push @errors, map { "exception $index: $_" } @entry_errors;
    push @rows, {
        package => $entry->{package} // '',
        version => $entry->{version} // '',
        owner => $entry->{owner} // '',
        expires_at => $entry->{expires_at} // '',
        status => @entry_errors ? 'invalid' : 'valid',
    };
}

write_report($report_path, \@rows, \@errors, $today);

if (@errors) {
    print STDERR "supply-chain exception ledger failed; see $report_path\n";
    print STDERR " - $_\n" for @errors;
    exit 1;
}

print "supply-chain exception ledger passed; see $report_path\n";
exit 0;

sub read_json {
    my ($path) = @_;
    open my $fh, '<', $path or die "open $path: $!";
    local $/;
    my $decoded = decode_json(<$fh>);
    close $fh;
    return $decoded;
}

sub non_empty_string {
    my ($value) = @_;
    return defined($value) && !ref($value) && $value =~ /\S/;
}

sub valid_ymd {
    my ($value) = @_;
    return 0 unless $value =~ /\A([0-9]{4})-([0-9]{2})-([0-9]{2})\z/;
    my ($year, $month, $day) = ($1, $2, $3);
    return 0 if $month < 1 || $month > 12 || $day < 1 || $day > 31;

    my $epoch = eval { timegm(0, 0, 0, $day, $month - 1, $year) };
    return 0 if $@;
    my @roundtrip = gmtime($epoch);
    return ($roundtrip[5] + 1900) == $year
      && ($roundtrip[4] + 1) == $month
      && $roundtrip[3] == $day;
}

sub markdown_escape {
    my ($value) = @_;
    $value =~ s/\|/\\|/g;
    $value =~ s/\r?\n/ /g;
    return $value;
}

sub write_report {
    my ($path, $rows, $errors, $today) = @_;
    open my $out, '>', $path or die "open $path: $!";
    print {$out} "# Supply-chain Exception Ledger\n\n";
    print {$out} "- Checked date: $today\n";
    print {$out} "- Required fields: package, version, reason, compensating_controls, owner, expires_at.\n";
    print {$out} "- Expired entries and entries without expiration are invalid.\n\n";
    print {$out} "| Package | Version | Owner | Expires | Status |\n";
    print {$out} "| --- | --- | --- | --- | --- |\n";
    for my $row (@{$rows}) {
        print {$out} '| '
          . join(
              ' | ',
              map { markdown_escape($_) }
                ($row->{package}, $row->{version}, $row->{owner}, $row->{expires_at}, $row->{status})
          )
          . " |\n";
    }
    print {$out} "\n";
    if (@{$errors}) {
        print {$out} "Errors:\n";
        print {$out} "- $_\n" for @{$errors};
    } else {
        print {$out} "Errors: none\n";
    }
    close $out;
}
