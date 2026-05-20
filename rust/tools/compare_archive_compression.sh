#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUST_DIR="$ROOT/rust"
OUT="${1:-$RUST_DIR/target/archive-comparison}"
KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
PASSPHRASE="lockbox-bench"
GNUPGHOME="$OUT/gnupg"

mkdir -p "$OUT/fixtures" "$OUT/results" "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

cargo build --release -p lockbox_cli --manifest-path "$RUST_DIR/Cargo.toml" >/dev/null
LOCKBOX="$RUST_DIR/target/release/lockbox"

bytes_of() {
  stat -c '%s' "$1"
}

fixture_bytes() {
  du -sb "$1" | awk '{print $1}'
}

generate_repeated_small() {
  local dir="$OUT/fixtures/repeated-small"
  [[ -d "$dir" ]] && return
  mkdir -p "$dir"
  perl -e '
    use strict;
    use warnings;
    my ($dir) = @ARGV;
    my $payload = "x" x 25600;
    for my $i (0..4095) {
      open my $fh, ">:raw", sprintf("%s/file-%04d.bin", $dir, $i) or die $!;
      print {$fh} $payload;
    }
  ' "$dir"
}

generate_text_tree() {
  local dir="$OUT/fixtures/text-tree"
  [[ -d "$dir" ]] && return
  mkdir -p "$dir"
  perl -e '
    use strict;
    use warnings;
    my ($dir) = @ARGV;
    for my $i (0..1023) {
      my $sub = sprintf("%s/service-%02d", $dir, $i % 16);
      mkdir $sub unless -d $sub;
      my $path = sprintf("%s/event-%04d.jsonl", $sub, $i);
      open my $fh, ">:raw", $path or die $!;
      for my $j (0..159) {
        printf {$fh}
          "{\"ts\":\"2026-05-%02dT%02d:%02d:%02dZ\",\"level\":\"%s\",\"service\":\"svc-%02d\",\"request_id\":\"req-%06d\",\"message\":\"%s\",\"value\":%d,\"ok\":%s}\n",
          1 + (($i + $j) % 28), $j % 24, ($i + $j) % 60, ($i * 7 + $j) % 60,
          ($j % 17 == 0 ? "WARN" : "INFO"), $i % 16, $i * 1000 + $j,
          ("cache lookup completed " x (1 + ($j % 4))), ($i * 31 + $j * 17) % 100000,
          ($j % 23 == 0 ? "false" : "true");
      }
    }
  ' "$dir"
}

generate_mixed_tree() {
  local dir="$OUT/fixtures/mixed-tree"
  local marker="$dir/.fixture-version"
  [[ -f "$marker" && "$(<"$marker")" == "mixed-v3" ]] && return
  rm -rf "$dir"
  mkdir -p "$dir/text" "$dir/bin" "$dir/tiny" "$dir/media"
  perl -e '
    use strict;
    use warnings;
    my ($dir) = @ARGV;
    for my $i (0..511) {
      open my $fh, ">:raw", sprintf("%s/text/doc-%04d.md", $dir, $i) or die $!;
      print {$fh} "# Document $i\n\n";
      for my $j (0..80) {
        print {$fh} "This paragraph has repeated project vocabulary, endpoint names, and status fields. ";
        print {$fh} "item=$i line=$j path=/api/v1/resource/" . ($i % 37) . "\n";
      }
    }
    for my $i (0..399) {
      open my $fh, ">:raw", sprintf("%s/tiny/key-%04d.txt", $dir, $i) or die $!;
      print {$fh} "flag-" . ($i % 13) . "\n";
    }
  ' "$dir"
  for i in $(seq 0 127); do
    dd if=/dev/zero bs=65536 count=1 2>/dev/null |
      openssl enc -aes-256-ctr -nosalt \
        -K 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
        -iv "$(printf '%032x' "$(((i + 1) * 1048576))")" \
        > "$(printf '%s/bin/blob-%04d.dat' "$dir" "$i")"
  done
  for i in $(seq 0 31); do
    printf 'PSEUDOIMAGE%08d' "$i" > "$(printf '%s/media/image-like-%04d.bin' "$dir" "$i")"
    dd if=/dev/zero bs=262144 count=1 2>/dev/null |
      openssl enc -aes-256-ctr -nosalt \
        -K ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100 \
        -iv "$(printf '%032x' "$(((i + 1000) * 1048576))")" \
        >> "$(printf '%s/media/image-like-%04d.bin' "$dir" "$i")"
  done
  echo "mixed-v3" > "$marker"
}

generate_high_entropy() {
  local dir="$OUT/fixtures/high-entropy"
  local marker="$dir/.fixture-version"
  [[ -f "$marker" && "$(<"$marker")" == "high-entropy-v3" ]] && return
  rm -rf "$dir"
  mkdir -p "$dir"
  for i in $(seq 0 63); do
    dd if=/dev/zero bs=1048576 count=1 2>/dev/null |
      openssl enc -aes-256-ctr -nosalt \
        -K 89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567 \
        -iv "$(printf '%032x' "$(((i + 1) * 1048576))")" \
        > "$(printf '%s/random-%04d.bin' "$dir" "$i")"
  done
  echo "high-entropy-v3" > "$marker"
}

generate_source_tree() {
  local dir="$OUT/fixtures/dvault-source"
  [[ -d "$dir" ]] && return
  mkdir -p "$dir"
  tar -C "$ROOT" -cf - \
    docs \
    rust/Cargo.toml \
    rust/Cargo.lock \
    rust/lockbox_cli/src \
    rust/lockbox_cli/tests \
    rust/lockbox_core/src \
    rust/lockbox_core/tests \
    rust/lockbox_core/examples \
    rust/lockbox_secure/src \
    rust/lockbox_vault/src \
    rust/lockbox_vault/tests \
    rust/tools | tar -C "$dir" -xf -
}

time_to() {
  local metric="$1"
  shift
  /usr/bin/time -f '%e	%M' -o "$metric" "$@"
}

run_tool() {
  local fixture="$1"
  local tool="$2"
  local src="$OUT/fixtures/$fixture"
  local result_dir="$OUT/results/$fixture"
  local metric="$result_dir/$tool.time"
  local artifact="$result_dir/$tool.out"
  mkdir -p "$result_dir"
  rm -f "$artifact" "$metric"

  case "$tool" in
    lockbox)
      local lb="$result_dir/lockbox.lbx"
      rm -f "$lb"
      time_to "$metric" "$LOCKBOX" --key "$KEY" create "$lb"
      time_to "$metric.add" "$LOCKBOX" --key "$KEY" add "$lb" "$src" /
      artifact="$lb"
      ;;
    gpg-default)
      time_to "$metric" env GNUPGHOME="$GNUPGHOME" bash -c \
        'tar -C "$1" -cf - . | gpg --batch --yes --pinentry-mode loopback --passphrase "$2" --symmetric --cipher-algo AES256 -o "$3"' \
        _ "$src" "$PASSPHRASE" "$artifact"
      ;;
    gpg-zlib9)
      time_to "$metric" env GNUPGHOME="$GNUPGHOME" bash -c \
        'tar -C "$1" -cf - . | gpg --batch --yes --pinentry-mode loopback --passphrase "$2" --symmetric --cipher-algo AES256 --compress-algo zlib --compress-level 9 -o "$3"' \
        _ "$src" "$PASSPHRASE" "$artifact"
      ;;
    zstd1-gpg-none)
      time_to "$metric" env GNUPGHOME="$GNUPGHOME" bash -c \
        'tar -C "$1" -cf - . | zstd -q -1 | gpg --batch --yes --pinentry-mode loopback --passphrase "$2" --symmetric --cipher-algo AES256 --compress-algo none -o "$3"' \
        _ "$src" "$PASSPHRASE" "$artifact"
      ;;
    zstd19-gpg-none)
      time_to "$metric" env GNUPGHOME="$GNUPGHOME" bash -c \
        'tar -C "$1" -cf - . | zstd -q -19 | gpg --batch --yes --pinentry-mode loopback --passphrase "$2" --symmetric --cipher-algo AES256 --compress-algo none -o "$3"' \
        _ "$src" "$PASSPHRASE" "$artifact"
      ;;
    *)
      echo "unknown tool: $tool" >&2
      return 2
      ;;
  esac

  local time_file="$metric"
  [[ "$tool" == "lockbox" ]] && time_file="$metric.add"
  local elapsed rss
  read -r elapsed rss < "$time_file"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$fixture" "$tool" "$(fixture_bytes "$src")" "$(bytes_of "$artifact")" "$elapsed" "$rss"
}

generate_repeated_small
generate_text_tree
generate_mixed_tree
generate_high_entropy
generate_source_tree

summary="$OUT/results/summary.tsv"
printf 'fixture\ttool\tlogical_bytes\toutput_bytes\tseconds\tmax_rss_kib\n' > "$summary"
for fixture in repeated-small text-tree mixed-tree high-entropy dvault-source; do
  for tool in lockbox gpg-default gpg-zlib9 zstd1-gpg-none zstd19-gpg-none; do
    run_tool "$fixture" "$tool" | tee -a "$summary"
  done
done

echo "summary: $summary"
