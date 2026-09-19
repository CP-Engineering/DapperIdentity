#!/usr/bin/env bash
# Checks a folder of packed nupkgs is the complete, self-consistent CPE.DapperIdentity set.
# Used by ci.yml and publish.yml, so a publish is held to exactly what CI checked.
# Usage: verify-packages.sh <artifacts-dir>
set -euo pipefail

DIR="${1:?artifacts dir required}"
IDS=(
  CPE.DapperIdentity.Abstractions
  CPE.DapperIdentity.Stores
  CPE.DapperIdentity.Jwt.Client
  CPE.DapperIdentity.Jwt.Server
  CPE.DapperIdentity.Cookies.Server
)

# The one lockstep version, from the same line publish.yml checks.
VERSION=$(grep -oPm1 '(?<=<Version>)[^<]+' Directory.Build.props)
echo "Expected version: $VERSION"

fail() { echo "::error::$1"; exit 1; }

COUNT=$(ls "$DIR"/*.nupkg | wc -l)
[ "$COUNT" -eq "${#IDS[@]}" ] || { ls "$DIR"; fail "Expected ${#IDS[@]} packages, found $COUNT."; }

for id in "${IDS[@]}"; do
  PKG="$DIR/$id.$VERSION.nupkg"
  [ -f "$PKG" ] || fail "$id $VERSION was not packed."

  CONTENT=$(unzip -l "$PKG")
  for f in README.md LICENSE lib/net8.0/ lib/net10.0/; do
    grep -q "$f" <<<"$CONTENT" || fail "$id is missing $f."
  done

  # Every dependency naming DapperIdentity must be one of the five, at exactly this version. The
  # match is deliberately wider than "CPE.": a project that lost its PackageId is depended on by
  # its bare project name (DapperIdentity.Abstractions), and that must fail here, not slip past.
  NUSPEC=$(unzip -p "$PKG" "$id.nuspec")
  while read -r dep; do
    [ -z "$dep" ] && continue
    depId=$(sed -E 's/.*id="([^"]+)".*/\1/' <<<"$dep")
    depVer=$(sed -E 's/.*version="([^"]+)".*/\1/' <<<"$dep")
    printf '%s\n' "${IDS[@]}" | grep -qx "$depId" \
      || fail "$id depends on $depId, which is not one of the packages this repo publishes."
    [ "$depVer" = "$VERSION" ] \
      || fail "$id depends on $depId $depVer, expected $VERSION. The set must move in lockstep."
    echo "  $id -> $depId $depVer"
  done < <(grep -o '<dependency id="[^"]*DapperIdentity[^/]*/>' <<<"$NUSPEC" | sort -u || true)
done

# The table scripts are the only record of the schema the stores expect.
STORES=$(unzip -l "$DIR/CPE.DapperIdentity.Stores.$VERSION.nupkg")
for f in sql/mysql.txt sql/Sqlite.txt; do
  # Print what IS there before failing, so the next miss explains itself from the CI log.
  grep -q "$f" <<<"$STORES" || { echo "$STORES"; fail "CPE.DapperIdentity.Stores is missing $f."; }
done

echo "All ${#IDS[@]} packages present at $VERSION, contents and dependencies consistent."
