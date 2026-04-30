#!/usr/bin/env bash
set -euo pipefail

mode="${1:-local}"
cargo_bin="${CARGO:-cargo}"
cargo_deny="${CARGO_DENY:-cargo deny}"
cargo_audit="${CARGO_AUDIT:-cargo audit}"
cargo_geiger="${CARGO_GEIGER:-cargo geiger}"
strict="${STRICT:-0}"
quality_dir="target/quality"

mkdir -p "${quality_dir}"

require_tool() {
  local name="$1"
  local command="$2"

  if ${command} --version >/dev/null 2>&1; then
    return 0
  fi

  if [[ "${strict}" == "1" ]]; then
    echo "${name} is required for strict supply-chain checks" >&2
    exit 127
  fi

  echo "${name} is not installed; skipping ${name} check" >&2
  return 1
}

metadata() {
  "${cargo_bin}" metadata --offline --locked --format-version=1 > "${quality_dir}/cargo-metadata.json"
}

deny_local() {
  if require_tool "cargo-deny" "${cargo_deny}"; then
    ${cargo_deny} check licenses bans sources
  fi
}

deny_strict() {
  if require_tool "cargo-deny" "${cargo_deny}"; then
    ${cargo_deny} check
  fi
}

audit_local() {
  if ! require_tool "cargo-audit" "${cargo_audit}"; then
    return 0
  fi

  if ${cargo_audit} --help 2>/dev/null | grep -q -- '--no-fetch'; then
    ${cargo_audit} --no-fetch --stale
    return 0
  fi

  if [[ "${strict}" == "1" ]]; then
    echo "cargo-audit does not support --no-fetch; refusing strict offline audit" >&2
    exit 127
  fi

  echo "cargo-audit lacks --no-fetch; skipping to avoid network access" >&2
}

audit_strict() {
  if require_tool "cargo-audit" "${cargo_audit}"; then
    ${cargo_audit}
  fi
}

unsafe_inventory() {
  local report="${quality_dir}/unsafe-inventory.md"
  local geiger_report="${quality_dir}/unsafe-inventory.geiger.md"

  metadata

  if require_tool "cargo-geiger" "${cargo_geiger}"; then
    if ${cargo_geiger} --all-features --output-format GitHubMarkdown > "${geiger_report}"; then
      {
        echo "# Unsafe Inventory"
        echo
        echo "- Tool: cargo-geiger"
        echo "- Scope: workspace, all features"
        echo "- Metadata: ${quality_dir}/cargo-metadata.json"
        echo
        cat "${geiger_report}"
      } > "${report}"
      rm -f "${geiger_report}"
      echo "wrote ${report}"
      return 0
    fi

    if [[ "${strict}" == "1" ]]; then
      echo "cargo-geiger failed during strict unsafe inventory" >&2
      exit 1
    fi

    echo "cargo-geiger failed; writing lexical unsafe inventory fallback" >&2
  else
    echo "cargo-geiger is not installed; writing lexical unsafe inventory fallback" >&2
  fi

  unsafe_inventory_fallback "${report}"
}

unsafe_inventory_fallback() {
  local report="$1"

  perl -MJSON::PP -MFile::Find=find -MFile::Basename=dirname -MFile::Spec -e '
    use strict;
    use warnings;

    my ($metadata_path, $report_path) = @ARGV;
    open my $metadata_fh, "<", $metadata_path or die "open $metadata_path: $!";
    local $/;
    my $metadata = decode_json(<$metadata_fh>);
    close $metadata_fh;

    my %workspace_members = map { $_ => 1 } @{ $metadata->{workspace_members} // [] };
    my @rows;

    for my $package (@{ $metadata->{packages} // [] }) {
      my $manifest = $package->{manifest_path} // next;
      my $root = dirname($manifest);
      next unless -d $root;

      my ($files, $tokens) = (0, 0);
      find(
        {
          wanted => sub {
            return unless -f $_;
            return unless /\.rs\z/;
            ++$files;
            open my $fh, "<", $_ or die "open $_: $!";
            while (my $line = <$fh>) {
              while ($line =~ /\bunsafe\b/g) {
                ++$tokens;
              }
            }
            close $fh;
          },
          no_chdir => 1,
        },
        $root,
      );

      push @rows, {
        name => $package->{name},
        version => $package->{version},
        scope => $workspace_members{$package->{id}} ? "workspace" : "dependency",
        files => $files,
        tokens => $tokens,
      };
    }

    @rows = sort {
      ($b->{scope} eq "workspace") <=> ($a->{scope} eq "workspace")
        || $a->{name} cmp $b->{name}
        || $a->{version} cmp $b->{version}
    } @rows;

    my $total_files = 0;
    my $total_tokens = 0;
    for my $row (@rows) {
      $total_files += $row->{files};
      $total_tokens += $row->{tokens};
    }

    open my $out, ">", $report_path or die "open $report_path: $!";
    print {$out} "# Unsafe Inventory\n\n";
    print {$out} "- Tool: lexical unsafe-token inventory fallback\n";
    print {$out} "- Scope: Cargo.lock packages from cargo metadata --offline --locked\n";
    print {$out} "- Metadata: target/quality/cargo-metadata.json\n";
    print {$out} "- Review trigger: run before public releases and after crypto, IPC, platform-verification, or storage dependency changes.\n";
    print {$out} "- Note: fallback counts `unsafe` tokens in Rust source and does not classify callsites like cargo-geiger.\n\n";
    print {$out} "| Package | Version | Scope | Rust files | unsafe tokens |\n";
    print {$out} "| --- | --- | --- | ---: | ---: |\n";
    for my $row (@rows) {
      print {$out} "| $row->{name} | $row->{version} | $row->{scope} | $row->{files} | $row->{tokens} |\n";
    }
    print {$out} "\n";
    print {$out} "Total Rust files: $total_files\n\n";
    print {$out} "Total unsafe tokens: $total_tokens\n";
    close $out;

    print "wrote $report_path\n";
  ' "${quality_dir}/cargo-metadata.json" "${report}"
}

sbom() {
  if command -v cargo-cyclonedx >/dev/null 2>&1; then
    cargo cyclonedx --format json --output-cdx --output-prefix "${quality_dir}/locket"
    return 0
  fi

  if [[ "${strict}" == "1" ]]; then
    echo "cargo-cyclonedx is required for strict SBOM generation" >&2
    exit 127
  fi

  echo "cargo-cyclonedx is not installed; writing metadata fallback only" >&2
  metadata
}

case "${mode}" in
  local)
    metadata
    deny_local
    audit_local
    ;;
  deny)
    metadata
    if [[ "${strict}" == "1" ]]; then
      deny_strict
    else
      deny_local
    fi
    ;;
  audit)
    if [[ "${strict}" == "1" ]]; then
      audit_strict
    else
      audit_local
    fi
    ;;
  unsafe)
    unsafe_inventory
    ;;
  sbom)
    sbom
    ;;
  strict)
    metadata
    deny_strict
    audit_strict
    unsafe_inventory
    sbom
    ;;
  *)
    echo "unknown supply-chain mode: ${mode}" >&2
    exit 2
    ;;
esac
