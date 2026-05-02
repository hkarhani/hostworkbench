#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Host Workbench"
DEFAULT_PORT="8443"
CERT_DAYS="3650"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CERT_DIR="${PROJECT_ROOT}/nginx/certs"
CERT_KEY="${CERT_DIR}/forescout-demo.key"
CERT_CRT="${CERT_DIR}/forescout-demo.crt"
ENV_FILE="${PROJECT_ROOT}/.env"

FORCE_CERT="false"
APP_HOST="${APP_HOST:-}"
APP_SSL_PORT="${APP_SSL_PORT:-${DEFAULT_PORT}}"

usage() {
  cat <<EOF
Usage: ./scripts/start_stack.sh [options]

Options:
  --host <hostname-or-ip>  Hostname/IP to include in the self-signed cert and printed URLs.
                           Default: auto-detected local IP, falling back to localhost.
  --port <port>            Published HTTPS port. Default: ${DEFAULT_PORT}.
  --force-cert             Regenerate nginx/certs/forescout-demo.{crt,key}.
  -h, --help               Show this help.

Environment overrides:
  APP_HOST=<host>          Same as --host.
  APP_SSL_PORT=<port>      Same as --port.
  JWT_SECRET=<secret>      Persisted to .env if .env does not already define it.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      APP_HOST="${2:-}"
      shift 2
      ;;
    --port)
      APP_SSL_PORT="${2:-}"
      shift 2
      ;;
    --force-cert)
      FORCE_CERT="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

detect_host() {
  if [[ -n "${APP_HOST}" ]]; then
    echo "${APP_HOST}"
    return
  fi

  if command -v hostname >/dev/null 2>&1; then
    local detected
    detected="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    if [[ -n "${detected}" ]]; then
      echo "${detected}"
      return
    fi
  fi

  if command -v ipconfig >/dev/null 2>&1; then
    local detected
    detected="$(ipconfig getifaddr en0 2>/dev/null || true)"
    if [[ -n "${detected}" ]]; then
      echo "${detected}"
      return
    fi
  fi

  echo "localhost"
}

is_ipv4() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

random_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    date +%s | shasum -a 256 | awk '{print $1}'
  fi
}

ensure_env() {
  touch "${ENV_FILE}"

  if ! grep -q '^APP_SSL_PORT=' "${ENV_FILE}"; then
    printf 'APP_SSL_PORT=%s\n' "${APP_SSL_PORT}" >> "${ENV_FILE}"
  else
    sed -i.bak "s/^APP_SSL_PORT=.*/APP_SSL_PORT=${APP_SSL_PORT}/" "${ENV_FILE}"
    rm -f "${ENV_FILE}.bak"
  fi

  if [[ -n "${JWT_SECRET:-}" ]]; then
    if grep -q '^JWT_SECRET=' "${ENV_FILE}"; then
      sed -i.bak "s/^JWT_SECRET=.*/JWT_SECRET=${JWT_SECRET}/" "${ENV_FILE}"
      rm -f "${ENV_FILE}.bak"
    else
      printf 'JWT_SECRET=%s\n' "${JWT_SECRET}" >> "${ENV_FILE}"
    fi
  elif ! grep -q '^JWT_SECRET=' "${ENV_FILE}"; then
    printf 'JWT_SECRET=%s\n' "$(random_secret)" >> "${ENV_FILE}"
  fi

  if ! grep -q '^JWT_EXPIRES_SECONDS=' "${ENV_FILE}"; then
    printf 'JWT_EXPIRES_SECONDS=3600\n' >> "${ENV_FILE}"
  fi
}

generate_cert() {
  local host="$1"
  mkdir -p "${CERT_DIR}"

  if [[ "${FORCE_CERT}" != "true" && -s "${CERT_KEY}" && -s "${CERT_CRT}" ]]; then
    echo "Using existing certificate: ${CERT_CRT}"
    return
  fi

  local san="DNS:localhost,IP:127.0.0.1"
  if [[ "${host}" != "localhost" ]]; then
    if is_ipv4 "${host}"; then
      san="${san},IP:${host}"
    else
      san="${san},DNS:${host}"
    fi
  fi

  echo "Generating self-signed certificate for ${host} (${san})"
  openssl req -x509 -nodes -days "${CERT_DAYS}" -newkey rsa:2048 \
    -keyout "${CERT_KEY}" \
    -out "${CERT_CRT}" \
    -subj "/CN=${host}" \
    -addext "subjectAltName=${san}" >/dev/null 2>&1
}

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    echo "Missing Docker Compose. Install Docker Compose v2 or docker-compose." >&2
    exit 1
  fi
}

main() {
  need_cmd docker
  need_cmd openssl

  local host
  host="$(detect_host)"

  cd "${PROJECT_ROOT}"
  ensure_env
  generate_cert "${host}"

  echo "Starting ${APP_NAME} stack on HTTPS port ${APP_SSL_PORT}..."
  compose up -d --build

  echo
  compose ps
  echo
  echo "${APP_NAME} is starting. URLs:"
  echo "  App:     https://${host}:${APP_SSL_PORT}/"
  echo "  Help:    https://${host}:${APP_SSL_PORT}/help"
  echo "  Swagger: https://${host}:${APP_SSL_PORT}/docs"
  echo
  echo "The certificate is self-signed. Browser warnings are expected; curl clients can use -k."
}

main
