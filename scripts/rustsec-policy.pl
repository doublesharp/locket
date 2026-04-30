#!/usr/bin/env perl
use strict;
use warnings;
use JSON::PP qw(decode_json);

my ($audit_json, $metadata_json, $report_path) = @ARGV;
die "usage: rustsec-policy.pl <cargo-audit-json> <cargo-metadata-json> <report.md>\n"
  unless defined $report_path;

my $audit = read_json($audit_json);
my $metadata = read_json($metadata_json);

my %scope_by_package = package_scopes($metadata);
my @findings = @{ $audit->{vulnerabilities}{list} // [] };
my @rows;
my $blocking = 0;

for my $finding (@findings) {
    my $advisory = $finding->{advisory} // {};
    my $package = $advisory->{package} // $finding->{package}{name} // 'unknown';
    my $version = $finding->{package}{version} // $advisory->{version} // '';
    my $scope = scope_for(\%scope_by_package, $package, $version);
    my $severity = severity_for($advisory);
    my ($decision, $blocks) = decision_for($severity, $scope);
    $blocking ||= $blocks;

    push @rows, {
        id => $advisory->{id} // 'unknown',
        package => $package,
        version => $version,
        severity => $severity,
        scope => $scope,
        decision => $decision,
        title => markdown_escape($advisory->{title} // ''),
    };
}

write_report($report_path, \@rows, $blocking);

if ($blocking) {
    print STDERR "RustSec policy failed; see $report_path\n";
    exit 1;
}

print "RustSec policy passed; see $report_path\n";
exit 0;

sub read_json {
    my ($path) = @_;
    open my $fh, '<', $path or die "open $path: $!";
    local $/;
    my $decoded = decode_json(<$fh>);
    close $fh;
    return $decoded;
}

sub package_scopes {
    my ($metadata) = @_;
    my %packages_by_id = map { $_->{id} => $_ } @{ $metadata->{packages} // [] };
    my %nodes_by_id = map { $_->{id} => $_ } @{ $metadata->{resolve}{nodes} // [] };
    my @workspace = @{ $metadata->{workspace_members} // [] };

    my %runtime_reachable;
    my %all_reachable;

    for my $root (@workspace) {
        traverse($root, \%nodes_by_id, \%runtime_reachable, 0);
        traverse($root, \%nodes_by_id, \%all_reachable, 1);
    }

    my %scopes;
    for my $id (keys %all_reachable) {
        my $package = $packages_by_id{$id} // next;
        my $key = package_key($package->{name}, $package->{version});
        my $scope = $runtime_reachable{$id} ? 'runtime' : 'dev-only';
        $scopes{$key} = merge_scope($scopes{$key}, $scope);
    }

    return %scopes;
}

sub traverse {
    my ($id, $nodes_by_id, $seen, $include_dev) = @_;
    return if $seen->{$id}++;

    my $node = $nodes_by_id->{$id} // return;
    for my $dep (@{ $node->{deps} // [] }) {
        next if !$include_dev && dep_is_dev_only($dep);
        traverse($dep->{pkg}, $nodes_by_id, $seen, $include_dev);
    }
}

sub dep_is_dev_only {
    my ($dep) = @_;
    my @kinds = @{ $dep->{dep_kinds} // [] };
    return 0 unless @kinds;
    for my $kind (@kinds) {
        return 0 if !defined $kind->{kind} || $kind->{kind} ne 'dev';
    }
    return 1;
}

sub package_key {
    my ($name, $version) = @_;
    return join "\0", $name // '', $version // '';
}

sub merge_scope {
    my ($left, $right) = @_;
    return $right unless defined $left;
    return 'runtime' if $left eq 'runtime' || $right eq 'runtime';
    return $left;
}

sub scope_for {
    my ($scopes, $package, $version) = @_;
    my $exact = $scopes->{package_key($package, $version)};
    return $exact if defined $exact;

    my %matches;
    for my $key (keys %{$scopes}) {
        my ($name) = split /\0/, $key;
        next unless $name eq $package;
        $matches{$scopes->{$key}} = 1;
    }

    return 'runtime' if $matches{'runtime'};
    return 'dev-only' if $matches{'dev-only'};
    return 'unknown';
}

sub severity_for {
    my ($advisory) = @_;
    my $severity = lc($advisory->{severity} // '');
    return $severity if $severity =~ /\A(?:critical|high|medium|low)\z/;

    my $cvss = $advisory->{cvss} // '';
    if ($cvss =~ /\A([0-9]+(?:\.[0-9]+)?)/) {
        my $score = $1 + 0;
        return 'critical' if $score >= 9.0;
        return 'high' if $score >= 7.0;
        return 'medium' if $score >= 4.0;
        return 'low' if $score > 0;
    }

    return 'unknown';
}

sub decision_for {
    my ($severity, $scope) = @_;
    return ('block', 1) if $severity eq 'critical' || $severity eq 'high';
    return ('block', 1) if $severity eq 'medium' && $scope ne 'dev-only';
    return ('dev-only exception required', 0) if $severity eq 'medium';
    return ('triage before release', 0) if $severity eq 'low';
    return ('block: unknown severity', 1);
}

sub markdown_escape {
    my ($value) = @_;
    $value =~ s/\|/\\|/g;
    $value =~ s/\r?\n/ /g;
    return $value;
}

sub write_report {
    my ($path, $rows, $blocking) = @_;
    open my $out, '>', $path or die "open $path: $!";
    print {$out} "# RustSec Advisory Policy\n\n";
    print {$out} "- High and critical advisories block.\n";
    print {$out} "- Medium runtime advisories block; medium dev-only advisories require an issue-linked exception.\n";
    print {$out} "- Low advisories require triage before release.\n";
    print {$out} "- Unknown severity blocks fail-closed.\n\n";
    print {$out} "| Advisory | Package | Version | Severity | Scope | Decision | Title |\n";
    print {$out} "| --- | --- | --- | --- | --- | --- | --- |\n";
    for my $row (@{$rows}) {
        print {$out} "| $row->{id} | $row->{package} | $row->{version} | $row->{severity} | $row->{scope} | $row->{decision} | $row->{title} |\n";
    }
    print {$out} "\n";
    print {$out} "Blocking advisories: " . ($blocking ? 'yes' : 'no') . "\n";
    close $out;
}
