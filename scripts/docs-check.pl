#!/usr/bin/env perl
use strict;
use warnings;
use File::Find qw(find);
use File::Spec;

my @required_specs = qw(
  index.md product.md invariants.md architecture.md data-model.md storage.md
  crypto.md project-cli.md policy.md runtime.md agent.md integrations.md
  scan-redaction.md desktop.md audit.md team-sync-recovery.md operations.md
  performance.md errors.md engineering.md testing.md fuzzing.md
);
my %required_specs = map { $_ => 1 } @required_specs;

my @errors;
for my $spec (@required_specs) {
    my $path = "docs/specs/$spec";
    push @errors, "missing required spec: $path" unless -f $path;
}

my @spec_files = sort map { s{\Adocs/specs/}{}r } glob 'docs/specs/*.md';
for my $spec (@spec_files) {
    push @errors, "unregistered spec file: docs/specs/$spec" unless $required_specs{$spec};
}

check_spec_index();
check_spec_backlinks();

my @markdown_files;
find(
    {
        wanted => sub {
            return unless -f $_;
            return unless /\.md\z/;
            push @markdown_files, $File::Find::name;
        },
        no_chdir => 1,
    },
    qw(README.md docs),
);

my %anchors_by_file;
for my $file (@markdown_files) {
    my %anchors;
    open my $fh, '<', $file or die "open $file: $!";
    while (my $line = <$fh>) {
        next unless $line =~ /^(#{1,6})\s+(.+?)\s*#*\s*$/;
        my $anchor = github_anchor($2);
        $anchors{$anchor} = 1 if length $anchor;
    }
    close $fh;
    $anchors_by_file{$file} = \%anchors;
}

for my $file (@markdown_files) {
    open my $fh, '<', $file or die "open $file: $!";
    my $line_number = 0;
    while (my $line = <$fh>) {
        ++$line_number;
        while ($line =~ /\[[^\]]+\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g) {
            my $target = $1;
            next if $target =~ m{\A(?:https?|mailto):};
            next if $target =~ m{\A#} && check_anchor($file, substr($target, 1));
            my ($path_part, $anchor) = split /#/, $target, 2;
            $path_part = uri_decode($path_part);
            my $linked = normalize_path(File::Spec->catfile(dirname($file), $path_part));
            if (!-f $linked) {
                push @errors, "$file:$line_number missing link target: $target";
                next;
            }
            if (defined $anchor && !check_anchor($linked, $anchor)) {
                push @errors, "$file:$line_number missing anchor '$anchor' in $linked";
            }
        }
    }
    close $fh;
}

if (@errors) {
    print STDERR "docs-check failed:\n";
    print STDERR " - $_\n" for @errors;
    exit 1;
}

print "docs-check passed\n";

sub check_spec_index {
    my $index = 'docs/specs/index.md';
    open my $fh, '<', $index or die "open $index: $!";
    my @reading_order;
    my $in_reading_order = 0;
    while (my $line = <$fh>) {
        if ($line =~ /^## Reading Order\s*$/) {
            $in_reading_order = 1;
            next;
        }
        last if $in_reading_order && $line =~ /^##\s+/;
        next unless $in_reading_order;
        push @reading_order, $1 if $line =~ /^\s*-\s+\[[^\]]+\]\(([^)#]+)(?:#[^)]+)?\)\s*$/;
    }
    close $fh;

    my @expected = grep { $_ ne 'index.md' } @required_specs;
    if (join("\n", @reading_order) ne join("\n", @expected)) {
        push @errors,
          "docs/specs/index.md Reading Order must match required spec list: "
          . "expected [@expected], found [@reading_order]";
    }
}

sub check_spec_backlinks {
    for my $spec (@required_specs) {
        next if $spec eq 'index.md';
        my $path = "docs/specs/$spec";
        next unless -f $path;
        open my $fh, '<', $path or die "open $path: $!";
        my $first_line = <$fh> // '';
        my $second_line = <$fh> // '';
        my $third_line = <$fh> // '';
        close $fh;
        my $preamble = join '', $first_line, $second_line, $third_line;
        if ($preamble !~ /\QStart at [index.md](index.md).\E/) {
            push @errors, "$path must start with a backlink to docs/specs/index.md";
        }
    }
}

sub dirname {
    my ($path) = @_;
    $path =~ s{/[^/]+\z}{};
    return length($path) ? $path : '.';
}

sub normalize_path {
    my ($path) = @_;
    my @parts;
    for my $part (split m{/+}, $path) {
        next if $part eq '' || $part eq '.';
        if ($part eq '..') {
            pop @parts if @parts;
            next;
        }
        push @parts, $part;
    }
    return join '/', @parts;
}

sub uri_decode {
    my ($value) = @_;
    $value =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
    return $value;
}

sub github_anchor {
    my ($heading) = @_;
    $heading =~ s/`([^`]*)`/$1/g;
    $heading = lc $heading;
    $heading =~ s/[^a-z0-9 _-]//g;
    $heading =~ s/\s+/-/g;
    $heading =~ s/^-+|-+$//g;
    return $heading;
}

sub check_anchor {
    my ($file, $anchor) = @_;
    return 1 if !defined($anchor) || $anchor eq '';
    $anchor = uri_decode(lc $anchor);
    return exists $anchors_by_file{$file}{$anchor};
}
