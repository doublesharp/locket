#!/usr/bin/env perl
use strict;
use warnings;
use JSON::PP qw(decode_json);

my %args = parse_args(@ARGV);
usage() if $args{help};

for my $required (qw(current mode report)) {
    die "missing --" . dash($required) . "\n" unless defined $args{$required} && length $args{$required};
}

die "--mode must be pr or release\n" unless $args{mode} eq 'pr' || $args{mode} eq 'release';

my $current = decode_json(read_file($args{current}));
my $baseline = defined $args{baseline} && length $args{baseline}
    ? decode_json(read_file($args{baseline}))
    : undef;
my $accepted_note = $args{accepted_regression_note} // '';

my %baseline_by_name;
if (defined $baseline) {
    for my $bench (@{ benchmarks($baseline) }) {
        next unless defined $bench->{name} && defined $bench->{p95_ms};
        $baseline_by_name{$bench->{name}} = $bench;
    }
}

my @rows;
my @failures;
my $hard_tolerance = $args{mode} eq 'pr' ? 1.10 : 1.00;

for my $bench (@{ benchmarks($current) }) {
    my $name = string_value($bench, 'name');
    my $p95_ms = number_value($bench, 'p95_ms');
    my $budget_ms = number_value($bench, 'budget_ms');
    my $allowed_ms = $budget_ms * $hard_tolerance;

    if ($p95_ms <= $allowed_ms) {
        push @rows, [$name, 'hard budget', 'passed',
            sprintf('p95 %.3f ms <= %.3f ms', $p95_ms, $allowed_ms)];
    } else {
        my $detail = sprintf('p95 %.3f ms > %.3f ms', $p95_ms, $allowed_ms);
        push @rows, [$name, 'hard budget', 'failed', $detail];
        push @failures, "$name hard budget: $detail";
    }

    next unless exists $baseline_by_name{$name};
    my $baseline_p95 = number_value($baseline_by_name{$name}, 'p95_ms');
    my $regression_limit = $baseline_p95 * 1.20;
    if ($p95_ms <= $regression_limit) {
        push @rows, [$name, 'tracked regression', 'passed',
            sprintf('p95 %.3f ms <= baseline %.3f ms + 20%%', $p95_ms, $baseline_p95)];
    } elsif (length $accepted_note) {
        push @rows, [$name, 'tracked regression', 'accepted',
            sprintf('p95 %.3f ms > baseline %.3f ms + 20%%; note recorded', $p95_ms, $baseline_p95)];
    } else {
        my $detail = sprintf('p95 %.3f ms > baseline %.3f ms + 20%%', $p95_ms, $baseline_p95);
        push @rows, [$name, 'tracked regression', 'failed', $detail];
        push @failures, "$name tracked regression: $detail";
    }
}

write_report($args{report}, \@rows, \@failures, $args{mode}, $accepted_note);

if (@failures) {
    print STDERR "benchmark policy failed; see $args{report}\n";
    print STDERR " - $_\n" for @failures;
    exit 1;
}

print "benchmark policy passed; see $args{report}\n";
exit 0;

sub parse_args {
    my @argv = @_;
    my %parsed;
    while (@argv) {
        my $arg = shift @argv;
        if ($arg eq '--help') {
            $parsed{help} = 1;
            next;
        }
        die "unknown argument: $arg\n" unless $arg =~ /\A--([a-z0-9-]+)\z/;
        my $key = $1;
        $key =~ tr/-/_/;
        die "missing value for $arg\n" unless @argv;
        $parsed{$key} = shift @argv;
    }
    return %parsed;
}

sub usage {
    print <<'USAGE';
usage: bench-policy.pl --current <summary.json> --mode <pr|release> --report <path>
       [--baseline <summary.json>] [--accepted-regression-note <text>]
USAGE
    exit 0;
}

sub dash {
    my ($value) = @_;
    $value =~ tr/_/-/;
    return $value;
}

sub read_file {
    my ($path) = @_;
    open my $fh, '<:raw', $path or die "open $path: $!";
    local $/;
    my $content = <$fh>;
    close $fh;
    return $content;
}

sub benchmarks {
    my ($summary) = @_;
    die "summary must be an object\n" unless ref($summary) eq 'HASH';
    die "summary benchmarks must be an array\n" unless ref($summary->{benchmarks}) eq 'ARRAY';
    return $summary->{benchmarks};
}

sub string_value {
    my ($object, $key) = @_;
    die "benchmark missing $key\n" unless ref($object) eq 'HASH' && defined $object->{$key} && !ref($object->{$key});
    return $object->{$key};
}

sub number_value {
    my ($object, $key) = @_;
    my $value = string_value($object, $key);
    die "benchmark $key must be numeric\n" unless $value =~ /\A[0-9]+(?:\.[0-9]+)?\z/;
    return 0 + $value;
}

sub write_report {
    my ($path, $rows, $failures, $mode, $accepted_note) = @_;
    my $dir = $path;
    $dir =~ s{/[^/]+\z}{};
    system('mkdir', '-p', $dir) == 0 or die "mkdir $dir failed" if length $dir && $dir ne $path;
    open my $out, '>', $path or die "open $path: $!";
    print {$out} "# Benchmark Policy\n\n";
    print {$out} "- mode: $mode\n";
    print {$out} "- hard_budget_tolerance: " . ($mode eq 'pr' ? '10%' : '0%') . "\n";
    print {$out} "- tracked_regression_tolerance: 20%\n";
    print {$out} "- accepted_regression_note: " . (length $accepted_note ? 'present' : 'absent') . "\n";
    print {$out} "- result: " . (@{$failures} ? 'failed' : 'passed') . "\n\n";
    print {$out} "| Benchmark | Check | Status | Detail |\n";
    print {$out} "| --- | --- | --- | --- |\n";
    for my $row (@{$rows}) {
        my ($name, $check, $status, $detail) = @{$row};
        $detail =~ s/\|/\\|/g;
        print {$out} "| $name | $check | $status | $detail |\n";
    }
    close $out;
}
