#!/bin/bash
# Generate a push password for one of Monk's registries and hand it to everything that needs
# it, without printing it: the Worker secrets, the GitHub repo that pushes to that registry,
# and optionally crane on a host over ssh. Running it again rotates the password.
#
#   scripts/monk-set-push-credentials.sh registry monk-io/monk [ssh-host]
#   scripts/monk-set-push-credentials.sh images   monk-io/monkec [ssh-host]
set -euo pipefail

env="${1:?usage: $0 <registry|images> <github-owner/repo> [ssh-host]}"
repo="${2:?usage: $0 <registry|images> <github-owner/repo> [ssh-host]}"
ssh_host="${3:-}"

case "$env" in
  registry) host=registry.monk.io ;;
  images) host=images.monk.io ;;
  *) echo "unknown registry: $env" >&2; exit 1 ;;
esac

cd "$(dirname "$0")/.."
user=ci
pass="$(openssl rand -hex 32)"

printf %s "$user" | wrangler secret put USERNAME --config wrangler.monk.jsonc --env "$env"
printf %s "$pass" | wrangler secret put PASSWORD --config wrangler.monk.jsonc --env "$env"
gh secret set CF_REGISTRY_USERNAME --repo "$repo" --body "$user"
printf %s "$pass" | gh secret set CF_REGISTRY_PASSWORD --repo "$repo"

if [ -n "$ssh_host" ]; then
  printf %s "$pass" | ssh "$ssh_host" "crane auth login $host -u $user --password-stdin"
fi

echo "push credentials for $host set on the Worker and on $repo${ssh_host:+ and $ssh_host}"
