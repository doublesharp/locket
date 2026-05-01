#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
quality_dir="${repo_root}/target/quality"
output="${LOCKET_REFERENCE_RUNNER_FINGERPRINT:-${quality_dir}/reference-runner-setup.json}"
steps_file="${LOCKET_REFERENCE_RUNNER_STEPS_FILE:-}"

mkdir -p "${quality_dir}"

perl -MJSON::PP -MTime::Piece -e '
  use strict;
  use warnings;

  my ($output, $steps_file) = @ARGV;

  sub command_output {
    my (@command) = @_;
    my $output = qx{@command 2>/dev/null};
    chomp $output;
    return length($output) ? $output : "unknown";
  }

  sub first_line {
    my ($value) = @_;
    $value =~ s/\r?\n.*\z//s;
    return length($value) ? $value : "unknown";
  }

  sub file_text {
    my ($path) = @_;
    return "unknown" if !defined($path) || !-r $path;
    open my $fh, "<", $path or return "unknown";
    local $/;
    my $text = <$fh>;
    chomp $text;
    return length($text) ? $text : "unknown";
  }

  sub steps {
    my ($path) = @_;
    return [] if !defined($path) || !length($path) || !-r $path;
    open my $fh, "<", $path or die "open $path: $!";
    my @steps;
    while (my $line = <$fh>) {
      chomp $line;
      my ($name, $status, $detail) = split /\t/, $line, 3;
      push @steps, {
        name => $name // "unknown",
        status => $status // "unknown",
        detail => $detail // "",
      };
    }
    return \@steps;
  }

  my $host_os = command_output("uname", "-s");
  my $filesystem = command_output("sh", "-c", "df -T . 2>/dev/null | awk '\''NR == 2 { print \$2 }'\'' || stat -f %T . 2>/dev/null");
  my $cpu = command_output("sh", "-c", "sysctl -n machdep.cpu.brand_string 2>/dev/null || awk -F: '\''/model name/ { sub(/^ /, \"\", \$2); print \$2; exit }'\'' /proc/cpuinfo 2>/dev/null");
  my $memory = command_output("sh", "-c", "sysctl -n hw.memsize 2>/dev/null || awk '\''/MemTotal/ { print \$2 * 1024; exit }'\'' /proc/meminfo 2>/dev/null");
  my $power = command_output("sh", "-c", "pmset -g batt 2>/dev/null | head -n 1 || true");
  my $thermal = command_output("sh", "-c", "pmset -g therm 2>/dev/null || true");
  my $governor = command_output("sh", "-c", "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || true");

  my $doc = {
    schema_version => 1,
    generated_at => gmtime->datetime . "Z",
    setup_class => $ENV{LOCKET_REFERENCE_RUNNER_CLASS} // "unknown",
    setup_script => $ENV{LOCKET_REFERENCE_RUNNER_SCRIPT} // "unknown",
    apply_mode => (($ENV{LOCKET_REFERENCE_RUNNER_APPLY} // "0") eq "1" ? "apply" : "dry-run"),
    repository => {
      root => command_output("git", "rev-parse", "--show-toplevel"),
      commit_sha => command_output("git", "rev-parse", "HEAD"),
      branch => command_output("git", "branch", "--show-current"),
    },
    host => {
      os => first_line(command_output("uname", "-srmo")),
      kernel => command_output("uname", "-r"),
      arch => command_output("uname", "-m"),
      cpu_model => first_line($cpu),
      memory_bytes => first_line($memory),
      filesystem_type => first_line($filesystem),
      power_state => first_line($power),
      thermal_state => $thermal,
      cpu_governor => first_line($governor),
      os_release => file_text("/etc/os-release"),
    },
    tools => {
      rustc => command_output("rustc", "-V"),
      cargo => command_output("cargo", "-V"),
      git => command_output("git", "--version"),
    },
    applied_state => steps($steps_file),
  };

  open my $out, ">", $output or die "open $output: $!";
  print {$out} JSON::PP->new->canonical->pretty->encode($doc);
' "${output}" "${steps_file}"

echo "wrote ${output}"
