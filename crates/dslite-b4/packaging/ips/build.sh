#!/bin/sh

set -eu

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
crate_dir=$(CDPATH= cd "$script_dir/../.." && pwd)
workspace_dir=$(CDPATH= cd "$crate_dir/../.." && pwd)

publisher=${PUBLISHER:-dslite-b4}
version=$(awk -F '"' '/^version = / { print $2; exit }' "$crate_dir/Cargo.toml")
output=${OUTPUT:-"$workspace_dir/target/dslite-b4-$version.p5p"}

die() {
    echo "error: $*" >&2
    exit 1
}

for command in awk cargo cp mkdir mktemp pkglint pkgdepend pkgfmt pkgmogrify pkgrecv pkgrepo pkgsend
do
    command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

[ "$(uname -s)" = SunOS ] || die "build this package natively on OmniOS"
[ -n "$version" ] || die "could not read the crate version"
[ ! -e "$output" ] || die "output already exists: $output"

work=$(mktemp -d "${TMPDIR:-/var/tmp}/dslite-b4-ips.XXXXXX")
chmod 0755 "$work"
cleanup() {
    status=$?
    if [ "$status" -eq 0 ]
    then
        rm -rf "$work"
    else
        echo "build artifacts retained in $work" >&2
    fi
}
trap cleanup 0
trap 'exit 1' 1 2 15

proto="$work/proto"
repo="$work/repo"
manifests="$work/manifests"
mkdir -p "$proto/usr/sbin" \
    "$proto/etc" \
    "$proto/lib/svc/manifest/network" \
    "$proto/lib/svc/method" \
    "$proto/usr/share/man/man5" \
    "$proto/usr/share/man/man8" \
    "$manifests"

cd "$workspace_dir"
cargo build --locked --release -p dslite-b4

cp "$workspace_dir/target/release/dslite-b4" "$proto/usr/sbin/dslite-b4"
cp "$crate_dir/example-config.toml" "$proto/etc/dslite-b4.toml"
cp "$crate_dir/packaging/smf/dslite-b4.xml" "$proto/lib/svc/manifest/network/dslite-b4.xml"
cp "$crate_dir/packaging/smf/dslite-b4" "$proto/lib/svc/method/dslite-b4"
cp "$crate_dir/packaging/man/dslite-b4.toml.5" "$proto/usr/share/man/man5/dslite-b4.toml.5"
cp "$crate_dir/packaging/man/generated/"*.8 "$proto/usr/share/man/man8/"
chmod 0755 "$proto/usr/sbin/dslite-b4" "$proto/lib/svc/method/dslite-b4"
chmod 0600 "$proto/etc/dslite-b4.toml"
chmod 0644 "$proto/lib/svc/manifest/network/dslite-b4.xml" \
    "$proto/usr/share/man/man5/dslite-b4.toml.5" \
    "$proto/usr/share/man/man8/"*.8

generated="$manifests/generated.p5m"
source_manifest="$manifests/source.p5m"
mogrified="$manifests/mogrified.p5m"
dependencies="$manifests/dependencies.p5m"
resolved_dir="$manifests/resolved"
final_manifest="$manifests/dslite-b4.p5m"

pkgsend generate "$proto" > "$generated"
{
    printf 'set name=pkg.fmri value=pkg://%s/network/dslite-b4@%s\n' "$publisher" "$version"
    printf 'set name=pkg.human-version value=%s\n' "$version"
    cat "$script_dir/dslite-b4.p5m"
    cat "$generated"
} > "$source_manifest"

pkgmogrify "$source_manifest" "$script_dir/transforms.mog" | pkgfmt > "$mogrified"
pkgdepend generate -m -d "$proto" -d "$crate_dir" "$mogrified" > "$dependencies"
mkdir "$resolved_dir"
pkgdepend resolve -m -d "$resolved_dir" "$dependencies"
pkgfmt < "$resolved_dir/dependencies.p5m" > "$final_manifest"
pkglint "$final_manifest"

pkgrepo create "$repo"
pkgrepo add-publisher -s "$repo" "$publisher"
pkgrepo set -s "$repo" "publisher/prefix=$publisher"
pkgrepo set -s "$repo" -p "$publisher" "repository/collection_type=supplemental"
pkgsend publish -s "$repo" -d "$proto" -d "$crate_dir" "$final_manifest"

mkdir -p "$(dirname "$output")"
pkgrecv -s "$repo" -d "$output" -a "pkg://$publisher/network/dslite-b4@$version"

echo "created $output"
echo "validate with: pfexec pkg install -n -v -g $output pkg://$publisher/network/dslite-b4@$version"
