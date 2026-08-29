#!/bin/bash
set -euo pipefail

repo="${BEEFAPI_CONFORMANCE_REPO:-Sunnyender-org/beefapi-conformance}"
token_id="${BEEFAPI_CONFORMANCE_TOKEN_ID:-2947}"
group="${BEEFAPI_CONFORMANCE_GROUP:-cursor-acceptance}"
exec_bin="${BEEFAPI_EXEC_BIN:-/Users/sunny/.codex/bin/beefapi-exec}"

[[ "$token_id" =~ ^[0-9]+$ ]] || { echo "token id must be numeric" >&2; exit 2; }
[[ "$group" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "group contains unsafe characters" >&2; exit 2; }
[[ -x "$exec_bin" ]] || { echo "beefapi-exec is unavailable" >&2; exit 2; }
command -v gh >/dev/null
command -v jq >/dev/null

db_query() {
  local encoded
  encoded=$(printf '%s' "$1" | base64 | tr -d '\r\n')
  "$exec_bin" --raw "printf '%s' '${encoded}' | base64 -d | docker exec -i beefapi-postgres sh -lc 'psql -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -Atq'" \
    | jq -er '.stdout'
}

token_sql="SELECT key FROM tokens WHERE id=${token_id} AND status=1 AND deleted_at IS NULL;"
token_key=$(db_query "$token_sql" | tr -d '\r\n')
[[ ${#token_key} -eq 48 ]] || { echo "acceptance token lookup failed" >&2; exit 1; }

channel_sql="SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (SELECT id,type,status,models,test_model,CASE WHEN NULLIF(btrim(setting),'') IS NULL THEN false ELSE COALESCE((setting::jsonb ->> 'cursor_agent_v1_native_web_search')::boolean,false) END AS cursor_agent_v1_native_web_search FROM channels WHERE status=1 AND position('${group}' in \"group\")>0 ORDER BY id) t;"
channels_json=$(db_query "$channel_sql" | tr -d '\r\n')
channel_count=$(jq -er 'if type=="array" and length>0 then length else error("empty channel snapshot") end' <<<"$channels_json")

printf '%s' "$token_key" | gh secret set BEEFAPI_CONFORMANCE_TOKEN --repo "$repo"
printf '%s' "$channels_json" | gh variable set BEEFAPI_CONFORMANCE_CHANNELS_JSON --repo "$repo"

echo "updated production conformance config: routes=${channel_count} group=${group}"
