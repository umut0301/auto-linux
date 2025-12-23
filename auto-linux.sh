#!/usr/bin/env bash
# auto-linux.sh - small helper for WireGuard client management
# Updated: 2025-12-23

set -euo pipefail
IFS=$'\n\t'

# Default interface name
WG_IFACE_DEFAULT="wg0"
CONFIG_DIR_DEFAULT="/etc/wireguard"
CLIENT_CONF_DIR_DEFAULT="/etc/wireguard/clients"

# Ensure client conf dir exists
mkdir -p "${CLIENT_CONF_DIR_DEFAULT}"

# Check for qrencode availability once
if command -v qrencode >/dev/null 2>&1; then
  QRENCODE_AVAILABLE=1
else
  QRENCODE_AVAILABLE=0
fi

# Helper: print error to stderr
err() {
  printf '%s\n' "$*" >&2
}

# Helper: show usage
usage() {
  cat <<EOF
Usage: ${0##*/} <command> [args]
Commands:
  wg_add_client NAME [INTERFACE] [CLIENT_IP]  - add a new WireGuard client
  wg_show_client NAME [INTERFACE]             - show client config
  wg_remove_client NAME [INTERFACE]           - remove a client

If INTERFACE is omitted, defaults to ${WG_IFACE_DEFAULT}.
CLIENT_IP is optional and if omitted the script will try to pick an available IP.
EOF
}

# Generate a new client config and keys
# Arguments: name, interface (optional), client_ip (optional)
wg_add_client() {
  local name="$1"
  local iface="${2:-$WG_IFACE_DEFAULT}"
  local client_ip="${3:-}"

  if [[ -z "$name" ]]; then
    err "wg_add_client: NAME is required"
    return 2
  fi

  local server_conf_path="$CONFIG_DIR_DEFAULT/${iface}.conf"
  local client_conf_path="$CLIENT_CONF_DIR_DEFAULT/${name}.conf"

  if [[ ! -f "$server_conf_path" ]]; then
    err "Server config not found at $server_conf_path"
    return 2
  fi

  if [[ -e "$client_conf_path" ]]; then
    err "Client configuration already exists: $client_conf_path"
    return 1
  fi

  # Generate keys
  local private_key
  local public_key
  private_key=$(wg genkey)
  public_key=$(printf '%s' "$private_key" | wg pubkey)

  # Determine client IP if not provided: try to find a free IP by scanning existing configs
  if [[ -z "$client_ip" ]]; then
    # Attempt to pick next available 10.0.0.x/24 or parse from server config AllowedIPs
    # This is a simple heuristic; adapt to your network plan.
    local base_net
    base_net=$(awk -F'=' '/^Address/ {gsub(/ /, "", $2); print $2; exit}' "$server_conf_path" || true)
    # base_net could be like 10.0.0.1/24
    if [[ -n "$base_net" && "$base_net" =~ ^([0-9]+\.[0-9]+\.[0-9]+)\. ]]; then
      local prefix="${BASH_REMATCH[1]}"
      local candidate=2
      while :; do
        local candidate_ip="${prefix}.${candidate}/32"
        if ! grep -Rq "${candidate_ip%%/32}" "$CLIENT_CONF_DIR_DEFAULT"; then
          client_ip="$candidate_ip"
          break
        fi
        ((candidate++)) || true
        if (( candidate > 250 )); then
          err "Unable to find free client IP"
          return 3
        fi
      done
    else
      # fallback
      client_ip="10.0.0.2/32"
    fi
  fi

  # Read server public key, endpoint, and allowed IPs from server config
  local server_pubkey
  local server_endpoint
  local server_listen_port
  server_pubkey=$(awk '/^# ServerPublicKey:/ {print $2; exit}' "$server_conf_path" || true)
  server_endpoint=$(awk -F'=' '/^Endpoint/ {gsub(/ /, "", $2); print $2; exit}' "$server_conf_path" || true)
  server_listen_port=$(awk -F'=' '/^ListenPort/ {gsub(/ /, "", $2); print $2; exit}' "$server_conf_path" || true)

  # Create client config file
  cat > "$client_conf_path" <<EOF
[Interface]
PrivateKey = ${private_key}
Address = ${client_ip}
DNS = 1.1.1.1

[Peer]
PublicKey = ${server_pubkey}
Endpoint = ${server_endpoint}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

  chmod 600 "$client_conf_path"

  # Append peer to server config
  cat >> "$server_conf_path" <<EOF

# Added client ${name}
[Peer]
# ${name}
PublicKey = ${public_key}
AllowedIPs = ${client_ip}
EOF

  echo "Client ${name} added. Config: ${client_conf_path}"

  # Offer QR code if qrencode is available
  if (( QRENCODE_AVAILABLE )); then
    if qrencode -o - -t PNG < "$client_conf_path" > "${client_conf_path}.png" 2>/dev/null; then
      echo "QR code written to ${client_conf_path}.png"
    else
      err "qrencode failed to create PNG"
    fi
  else
    err "Note: qrencode not found. Skipping QR code generation. Install qrencode to enable QR output."
  fi
}

# Show client config or summary
# Arguments: name, interface (optional)
wg_show_client() {
  local name="$1"
  local iface="${2:-$WG_IFACE_DEFAULT}"

  if [[ -z "$name" ]]; then
    err "wg_show_client: NAME is required"
    return 2
  fi

  local client_conf_path="$CLIENT_CONF_DIR_DEFAULT/${name}.conf"

  if [[ ! -f "$client_conf_path" ]]; then
    err "Client config not found: $client_conf_path"
    return 1
  fi

  echo "=== Client configuration: $client_conf_path ==="
  cat "$client_conf_path"

  if (( QRENCODE_AVAILABLE )); then
    if [[ -f "${client_conf_path}.png" ]]; then
      echo "QR code image: ${client_conf_path}.png"
    else
      # Attempt to create a QR code on the fly (stdout PNG)
      if qrencode -o - -t PNG < "$client_conf_path" > "${client_conf_path}.png" 2>/dev/null; then
        echo "QR code written to ${client_conf_path}.png"
      else
        err "Failed to generate QR code PNG for ${name}"
      fi
    fi
  else
    err "Note: qrencode not found. To generate QR codes, install qrencode."
  fi
}

# Remove a client (removes client config and its peer block in server conf)
# Arguments: name, interface (optional)
wg_remove_client() {
  local name="$1"
  local iface="${2:-$WG_IFACE_DEFAULT}"

  if [[ -z "$name" ]]; then
    err "wg_remove_client: NAME is required"
    return 2
  fi

  local server_conf_path="$CONFIG_DIR_DEFAULT/${iface}.conf"
  local client_conf_path="$CLIENT_CONF_DIR_DEFAULT/${name}.conf"

  if [[ ! -f "$server_conf_path" ]]; then
    err "Server config not found at $server_conf_path"
    return 2
  fi

  if [[ ! -f "$client_conf_path" ]]; then
    err "Client config not found: $client_conf_path"
    return 1
  fi

  # Extract public key from client config
  local client_pubkey
  client_pubkey=$(awk -F'=' '/^PublicKey/ {gsub(/ /, "", $2); print $2; exit}' "$client_conf_path" || true)

  # Remove peer block(s) containing that public key from server config
  if [[ -n "$client_pubkey" ]]; then
    # Create a temporary file safely
    local tmpfile
    tmpfile=$(mktemp)
    awk -v pk="$client_pubkey" '
      BEGIN {inpeer=0; skip=0}
      /^\[Peer\]/ {inpeer=1; buffer=$0; next}
      {
        if(inpeer){ buffer=buffer"\n"$0 }
        else { print $0 }
      }
      /PublicKey/ {
        if ($0 ~ pk) { skip=1 }
      }
      /^$/ {
        if (inpeer) {
          if (!skip) { print buffer "\n" }
          inpeer=0; skip=0; buffer=""
        }
      }
      END {
        if (inpeer && !skip) print buffer
      }
    ' "$server_conf_path" > "$tmpfile"
    mv "$tmpfile" "$server_conf_path"
  else
    err "Could not determine public key from $client_conf_path; manual removal may be required."
  fi

  # Remove client files
  rm -f "$client_conf_path" "${client_conf_path}.png"
  echo "Client ${name} removed"
}

# Simple CLI dispatch
if [[ ${#@} -lt 1 ]]; then
  usage
  exit 1
fi

cmd="$1"
shift || true
case "$cmd" in
  wg_add_client)
    wg_add_client "$@"
    ;;
  wg_show_client)
    wg_show_client "$@"
    ;;
  wg_remove_client)
    wg_remove_client "$@"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    err "Unknown command: $cmd"
    usage
    exit 2
    ;;
esac
