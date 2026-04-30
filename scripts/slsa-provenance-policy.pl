#!/usr/bin/env perl
use strict;
use warnings;
use Digest::SHA qw(sha256_hex);
use JSON::PP qw(decode_json);
use MIME::Base64 qw(decode_base64);

my %args = parse_args(@ARGV);
usage() if $args{help};

for my $required (qw(artifact provenance expected_repository expected_builder expected_build_type expected_workflow)) {
    die "missing --" . dash($required) . "\n" unless defined $args{$required} && length $args{$required};
}

my $report = $args{report} // 'target/quality/slsa-provenance-policy.md';
my @checks;
my @errors;

my $artifact_sha = file_sha256($args{artifact});
my $raw = read_file($args{provenance});
my ($statement, $signature_state) = provenance_statement($raw);

check_equals('predicateType', $statement->{predicateType}, 'https://slsa.dev/provenance/v1');
check_subject_digest($statement, $artifact_sha, $args{artifact});
check_equals('builder.id', builder_id($statement), $args{expected_builder});
check_equals('buildType', build_type($statement), $args{expected_build_type});
check_equals('source.repository', source_repository($statement), $args{expected_repository});
check_equals('workflow', workflow_ref($statement), $args{expected_workflow});

if ($args{require_signature}) {
    check_truth('provenance signature', $signature_state eq 'present',
        "provenance contains at least one DSSE/in-toto signature");
}

if ($args{require_build_l3}) {
    my $builder = builder_id($statement) // '';
    my $hosted = $builder =~ m{\Ahttps://github\.com/actions/runner/}
        || $builder =~ m{\Ahttps://github\.com/Attestations/GitHubHostedActions@}
        || $builder =~ m{\Ahttps://github\.com/doublesharp/locket/\.github/workflows/};
    check_truth('Build L3 hosted-runner target', $hosted,
        'builder identity is a hosted CI builder, not a local workstation');
}

write_report($report, \@checks, \@errors, $artifact_sha);

if (@errors) {
    print STDERR "SLSA provenance policy failed; see $report\n";
    print STDERR " - $_\n" for @errors;
    exit 1;
}

print "SLSA provenance policy passed; see $report\n";
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
        if ($arg eq '--require-signature') {
            $parsed{require_signature} = 1;
            next;
        }
        if ($arg eq '--require-build-l3') {
            $parsed{require_build_l3} = 1;
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
usage: slsa-provenance-policy.pl --artifact <path> --provenance <json>
       --expected-repository <uri> --expected-builder <id>
       --expected-build-type <type> --expected-workflow <ref>
       [--require-signature] [--require-build-l3] [--report <path>]
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

sub file_sha256 {
    my ($path) = @_;
    open my $fh, '<:raw', $path or die "open $path: $!";
    my $ctx = Digest::SHA->new(256);
    $ctx->addfile($fh);
    close $fh;
    return $ctx->hexdigest;
}

sub provenance_statement {
    my ($raw) = @_;
    my $json = decode_json($raw);
    if (ref($json) eq 'HASH' && exists $json->{payload} && exists $json->{payloadType}) {
        my $payload = decode_base64($json->{payload});
        my $statement = decode_json($payload);
        my $signatures = $json->{signatures};
        my $signature_state = ref($signatures) eq 'ARRAY' && @{$signatures} ? 'present' : 'missing';
        return ($statement, $signature_state);
    }
    if (ref($json) eq 'HASH' && ref($json->{signatures}) eq 'ARRAY' && @{ $json->{signatures} }) {
        return ($json, 'present');
    }
    return ($json, 'unchecked');
}

sub check_equals {
    my ($name, $actual, $expected) = @_;
    if (defined $actual && $actual eq $expected) {
        push @checks, [$name, 'passed', $actual];
        return;
    }
    my $detail = defined $actual ? "expected $expected, got $actual" : "expected $expected, got <missing>";
    push @checks, [$name, 'failed', $detail];
    push @errors, "$name: $detail";
}

sub check_truth {
    my ($name, $ok, $detail) = @_;
    push @checks, [$name, $ok ? 'passed' : 'failed', $detail];
    push @errors, "$name: $detail" unless $ok;
}

sub check_subject_digest {
    my ($statement, $artifact_sha, $artifact_path) = @_;
    my $subjects = $statement->{subject};
    if (ref($subjects) ne 'ARRAY') {
        push @checks, ['subject digest', 'failed', 'subject array missing'];
        push @errors, 'subject digest: subject array missing';
        return;
    }
    for my $subject (@{$subjects}) {
        next unless ref($subject) eq 'HASH';
        my $digest = $subject->{digest};
        next unless ref($digest) eq 'HASH';
        if (($digest->{sha256} // '') eq $artifact_sha) {
            push @checks, ['subject digest', 'passed', "sha256=$artifact_sha"];
            return;
        }
    }
    push @checks, ['subject digest', 'failed', "artifact sha256 $artifact_sha not present"];
    push @errors, "subject digest: artifact sha256 $artifact_sha not present";
}

sub builder_id {
    my ($statement) = @_;
    return nested($statement, qw(predicate runDetails builder id))
        // nested($statement, qw(predicate builder id));
}

sub build_type {
    my ($statement) = @_;
    return nested($statement, qw(predicate buildDefinition buildType))
        // nested($statement, qw(predicate buildType));
}

sub source_repository {
    my ($statement) = @_;
    return nested($statement, qw(predicate buildDefinition externalParameters repository))
        // nested($statement, qw(predicate buildDefinition externalParameters sourceRepository))
        // nested($statement, qw(predicate buildDefinition externalParameters gitRepository))
        // nested($statement, qw(predicate invocation configSource uri));
}

sub workflow_ref {
    my ($statement) = @_;
    return nested($statement, qw(predicate buildDefinition externalParameters workflow))
        // nested($statement, qw(predicate buildDefinition externalParameters workflow_ref))
        // nested($statement, qw(predicate buildDefinition externalParameters github_workflow_ref))
        // nested($statement, qw(predicate invocation configSource entryPoint));
}

sub nested {
    my ($value, @path) = @_;
    for my $key (@path) {
        return undef unless ref($value) eq 'HASH' && exists $value->{$key};
        $value = $value->{$key};
    }
    return ref($value) ? undef : $value;
}

sub write_report {
    my ($path, $checks, $errors, $artifact_sha) = @_;
    my $dir = $path;
    $dir =~ s{/[^/]+\z}{};
    system('mkdir', '-p', $dir) == 0 or die "mkdir $dir failed" if length $dir && $dir ne $path;
    open my $out, '>', $path or die "open $path: $!";
    print {$out} "# SLSA Provenance Policy\n\n";
    print {$out} "- Artifact SHA-256: $artifact_sha\n";
    print {$out} "- Result: " . (@{$errors} ? 'failed' : 'passed') . "\n\n";
    print {$out} "| Check | Status | Detail |\n";
    print {$out} "| --- | --- | --- |\n";
    for my $check (@{$checks}) {
        my ($name, $status, $detail) = @{$check};
        $detail =~ s/\|/\\|/g;
        print {$out} "| $name | $status | $detail |\n";
    }
    close $out;
}
