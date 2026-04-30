#!/usr/bin/env perl
use strict;
use warnings;
use Digest::SHA qw(sha256_hex);
use JSON::PP qw(encode_json);
use File::Path qw(make_path remove_tree);

my %args = parse_args(@ARGV);
usage() if $args{help};

my $profile = $args{profile} // 'smoke';
my $out = $args{out} // 'target/bench-fixtures';
die "--profile must be smoke, pr, or release\n" unless $profile =~ /\A(?:smoke|pr|release)\z/;

umask 0077;
remove_tree($out) if -d $out;
make_path($out, { mode => 0700 });

my %sizes = profile_sizes($profile);
write_metadata_fixture("$out/metadata");
write_runtime_fixture("$out/runtime");
write_reference_fixture("$out/reference-resolution");
write_scan_fixture("$out/staged-scan", $sizes{staged_scan_bytes});
write_full_scan_fixture("$out/full-scan", $sizes{full_scan_bytes});
write_argon2_fixture("$out/argon2");
write_manifest("$out/manifest.json", $profile, \%sizes);

print "benchmark fixtures written to $out ($profile)\n";
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
usage: bench-fixtures.pl [--profile smoke|pr|release] [--out <dir>]
USAGE
    exit 0;
}

sub profile_sizes {
    my ($profile) = @_;
    return (
        staged_scan_bytes => 96 * 1024,
        full_scan_bytes => 1 * 1024 * 1024,
    ) if $profile eq 'smoke';
    return (
        staged_scan_bytes => 2 * 1024 * 1024,
        full_scan_bytes => 250 * 1024 * 1024,
    ) if $profile eq 'pr';
    return (
        staged_scan_bytes => 2 * 1024 * 1024,
        full_scan_bytes => 1024 * 1024 * 1024,
    );
}

sub write_metadata_fixture {
    my ($dir) = @_;
    make_path($dir, { mode => 0700 });
    my @profiles = map {
        {
            profile_id => sprintf('profile-%02d', $_),
            name_alias => sprintf('profile-label-%02d', $_),
        }
    } 1..3;
    my @secrets;
    for my $idx (1..150) {
        push @secrets, {
            secret_id => sprintf('secret-%03d', $idx),
            name_alias => sprintf('secret-label-%03d', $idx),
            profile_id => $profiles[($idx - 1) % @profiles]->{profile_id},
            state => $idx <= 50 ? 'active' : 'metadata-only',
            current_version => $idx <= 50 ? 1 : undef,
            value_materialized => JSON::PP::false,
        };
    }
    my @policies = map {
        {
            policy_id => sprintf('policy-%02d', $_),
            command_alias => sprintf('policy-command-%02d', $_),
            required_secret_aliases => [ map { sprintf('secret-label-%03d', $_) } $_..($_ + 4) ],
        }
    } 1..10;
    my @trusted_roots = map {
        {
            root_id => sprintf('trusted-root-%02d', $_),
            path_alias => sprintf('root-label-%02d', $_),
        }
    } 1..5;
    my @audit = map {
        {
            sequence => $_,
            action => $_ == 1 ? 'INIT' : 'METADATA_FIXTURE',
            hmac_ok => JSON::PP::true,
            prev_hmac_digest => sha256_hex("prev:$_"),
        }
    } 1..25;
    write_json("$dir/project.json", {
        fixture => 'metadata',
        profiles => \@profiles,
        secrets => \@secrets,
        policies => \@policies,
        trusted_roots => \@trusted_roots,
        audit_chain => \@audit,
    });
}

sub write_runtime_fixture {
    my ($dir) = @_;
    make_path($dir, { mode => 0700 });
    my @secrets;
    for my $idx (1..50) {
        my $bytes = 16 + (($idx * 83) % (4096 - 16));
        push @secrets, {
            env_name => sprintf('SECRET_%03d', $idx),
            value_bytes => $bytes,
            value_seed_digest => sha256_hex("runtime-value-seed:$idx:$bytes"),
            plaintext_persisted => JSON::PP::false,
        };
    }
    my @refs = map { sprintf('lk://profile-label-01/SECRET_%03d', $_) } 1..10;
    write_json("$dir/runtime.json", {
        fixture => 'runtime',
        active_secret_count => 50,
        policy_name => 'runtime-all-secrets',
        secret_material => \@secrets,
        references => \@refs,
    });
}

sub write_reference_fixture {
    my ($dir) = @_;
    make_path($dir, { mode => 0700 });
    my @states = qw(current pinned_current deprecated_in_grace expired missing unauthorized);
    my @refs;
    for my $idx (1..500) {
        my $state = $states[($idx - 1) % @states];
        my $version = $state =~ /pinned|deprecated|expired/ ? '@v2' : '';
        push @refs, {
            uri => sprintf('lk://profile-label-%02d/SECRET_%03d%s', (($idx - 1) % 3) + 1, $idx, $version),
            expected_state => $state,
            value_seed_digest => $state =~ /missing|unauthorized/ ? undef : sha256_hex("reference-value-seed:$idx"),
        };
    }
    write_json("$dir/references.json", {
        fixture => 'reference-resolution',
        references => \@refs,
    });
}

sub write_scan_fixture {
    my ($dir, $target_bytes) = @_;
    make_path("$dir/repo/src", "$dir/repo/.env.d", { mode => 0700 });
    my $bytes = 0;
    $bytes += write_sized_file("$dir/repo/src/app.txt", $target_bytes / 2, "provider-shaped-token AKIAIOSFODNN7EXAMPLE\n");
    $bytes += write_sized_file("$dir/repo/.env.d/local.env", $target_bytes / 4, "PUBLIC_PLACEHOLDER=fixture\n");
    $bytes += write_sized_file("$dir/repo/src/high-entropy.txt", $target_bytes - $bytes, "Zml4dHVyZS1oaWdoLWVudHJvcHktbm90LWEtc2VjcmV0\n");
    write_json("$dir/manifest.json", {
        fixture => 'staged-scan',
        bytes => $bytes,
        notes => 'Synthetic invalid tokens and deterministic high-entropy-looking text only.',
    });
}

sub write_full_scan_fixture {
    my ($dir, $target_bytes) = @_;
    make_path("$dir/repo/src/nested", "$dir/repo/ignored", "$dir/repo/bin", { mode => 0700 });
    write_file("$dir/repo/.gitignore", "ignored/\n");
    my $remaining = $target_bytes;
    my @files = (
        ["$dir/repo/src/nested/generated-a.txt", "text", int($target_bytes * 0.30)],
        ["$dir/repo/src/nested/generated-b.txt", "text", int($target_bytes * 0.25)],
        ["$dir/repo/ignored/build.log", "ignored", int($target_bytes * 0.15)],
        ["$dir/repo/bin/blob.bin", "binary", int($target_bytes * 0.20)],
    );
    my $written = 0;
    for my $file (@files) {
        my ($path, $kind, $bytes) = @{$file};
        $written += write_sized_file($path, $bytes, "$kind fixture line " . sha256_hex($path) . "\n");
        $remaining -= $bytes;
    }
    $written += write_sized_file("$dir/repo/src/remainder.txt", $remaining, "remainder fixture line\n") if $remaining > 0;
    write_json("$dir/manifest.json", {
        fixture => 'full-scan',
        requested_bytes => $target_bytes,
        written_bytes => $written,
        includes_ignored_paths => JSON::PP::true,
        includes_binary_paths => JSON::PP::true,
    });
}

sub write_argon2_fixture {
    my ($dir) = @_;
    make_path($dir, { mode => 0700 });
    write_json("$dir/argon2.json", {
        fixture => 'argon2',
        passphrase_fallback => {
            kdf => 'argon2id',
            memory_kib => 65536,
            iterations => 3,
            parallelism => 1,
            test_passphrase_seed_digest => sha256_hex('argon2-passphrase-fixture'),
            test_salt_digest => sha256_hex('argon2-passphrase-salt'),
            plaintext_persisted => JSON::PP::false,
        },
        recovery_envelope => {
            kdf => 'argon2id',
            memory_kib => 262144,
            iterations => 4,
            parallelism => 1,
            test_recovery_code_seed_digest => sha256_hex('argon2-recovery-fixture'),
            test_salt_digest => sha256_hex('argon2-recovery-salt'),
            plaintext_persisted => JSON::PP::false,
        },
    });
}

sub write_manifest {
    my ($path, $profile, $sizes) = @_;
    write_json($path, {
        schema => 'locket-bench-fixtures-v1',
        profile => $profile,
        generated_content => 'deterministic synthetic metadata and corpora',
        plaintext_secrets_persisted => JSON::PP::false,
        staged_scan_bytes => $sizes->{staged_scan_bytes},
        full_scan_bytes => $sizes->{full_scan_bytes},
        fixtures => [
            'metadata',
            'runtime',
            'reference-resolution',
            'staged-scan',
            'full-scan',
            'argon2',
        ],
    });
}

sub write_sized_file {
    my ($path, $target_bytes, $seed) = @_;
    $target_bytes = int($target_bytes);
    open my $fh, '>:raw', $path or die "open $path: $!";
    my $written = 0;
    my $counter = 0;
    while ($written < $target_bytes) {
        my $line = sprintf('%08d %s %s', $counter, $seed, sha256_hex("$path:$counter")) . "\n";
        my $remaining = $target_bytes - $written;
        if (length($line) > $remaining) {
            print {$fh} substr($line, 0, $remaining);
            $written += $remaining;
            last;
        }
        print {$fh} $line;
        $written += length($line);
        $counter++;
    }
    close $fh;
    chmod 0600, $path or die "chmod $path: $!";
    return $written;
}

sub write_json {
    my ($path, $value) = @_;
    write_file($path, JSON::PP->new->canonical->pretty->encode($value));
}

sub write_file {
    my ($path, $content) = @_;
    open my $fh, '>:raw', $path or die "open $path: $!";
    print {$fh} $content;
    close $fh;
    chmod 0600, $path or die "chmod $path: $!";
}
