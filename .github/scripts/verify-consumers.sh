#!/usr/bin/env bash
# Installs the packed CPE.DapperIdentity set into throwaway apps from a local feed and builds them,
# on both target frameworks. Package metadata can read correctly and still fail to restore; only a
# real consumer proves it doesn't.
# Usage: verify-consumers.sh <absolute-artifacts-dir>
set -euo pipefail

FEED="${1:?absolute artifacts dir required}"
VERSION=$(grep -oPm1 '(?<=<Version>)[^<]+' Directory.Build.props)
WORK=$(mktemp -d)

# Local feed first, nuget.org for everything else (Dapper, JwtBearer, ...). No other sources, so a
# package that only resolves from a developer's machine cannot sneak through.
write_nuget_config() {
  cat > "$1/nuget.config" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local" value="$FEED" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
EOF
}

consume() {
  local template="$1" tfm="$2"; shift 2
  local dir="$WORK/$template-$tfm"
  echo "::group::$template on $tfm: ${*}"
  dotnet new "$template" -o "$dir" -f "$tfm" --no-https
  write_nuget_config "$dir"
  for id in "$@"; do
    dotnet add "$dir" package "$id" --version "$VERSION"
  done
  dotnet build "$dir" -c Release
  echo "::endgroup::"
}

for tfm in net8.0 net10.0; do
  # Both server packages side by side, as an API that also serves cookie-authenticated pages would.
  consume webapi "$tfm" CPE.DapperIdentity.Jwt.Server CPE.DapperIdentity.Cookies.Server
  # The browser client: must restore without dragging in the Dapper stack.
  consume blazorwasm "$tfm" CPE.DapperIdentity.Jwt.Client
done

# A WebAssembly app has no business carrying Dapper; its resolved graph proves it does not.
# Control first: the server consumer DOES take Dapper through Stores, so the same grep must find it
# there - otherwise an assets-file format change would make the check below pass vacuously.
for tfm in net8.0 net10.0; do
  grep -q '"Dapper/' "$WORK/webapi-$tfm/obj/project.assets.json" \
    || { echo "::error::Control failed: no Dapper entry found in the server consumer on $tfm, so the client check cannot be trusted."; exit 1; }
  ASSETS="$WORK/blazorwasm-$tfm/obj/project.assets.json"
  if grep -q '"Dapper/' "$ASSETS"; then
    echo "::error::The Jwt.Client consumer on $tfm resolved Dapper. The client package has picked up the storage layer."
    exit 1
  fi
done

echo "Every consumer restored and built against $VERSION from the local feed."
