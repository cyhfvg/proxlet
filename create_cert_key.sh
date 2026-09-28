#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR

OUTPUT_DIR="${SCRIPT_DIR}/certs"
COMMON_NAME="localhost"
DAYS="825"
FORCE=0
declare -a SUBJECT_ALTERNATIVE_NAMES=("DNS:localhost" "IP:127.0.0.1" "IP:::1")
TEMPORARY_DIRECTORY=""

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Generate a local CA and a certificate/key pair for proxlet HTTPS proxy mode.

Options:
  -o, --output-dir <DIR>  Output directory. Default: ${OUTPUT_DIR}
      --common-name <CN>  Certificate common name. Default: ${COMMON_NAME}
      --san <TYPE:VALUE>  Add a subject alternative name, for example:
                          DNS:proxy.example.com or IP:192.0.2.10
                          May be repeated.
      --days <DAYS>       Certificate validity period. Default: ${DAYS}
  -f, --force             Replace existing generated files.
  -h, --help              Print this help message.

Generated files:
  proxlet-ca.pem          CA certificate to trust on proxy clients
  proxlet-ca-key.pem      CA private key; keep this file private
  proxlet-cert.pem        Certificate for proxlet --tls-cert
  proxlet-key.pem         Private key for proxlet --tls-key
EOF
}

log() {
    printf '[create_cert_key] %s\n' "$*"
}

die() {
    printf '[create_cert_key] error: %s\n' "$*" >&2
    exit 1
}

run_openssl() {
    local stderr_file="${TEMPORARY_DIRECTORY}/openssl.err"
    if ! "$@" >/dev/null 2>"${stderr_file}"; then
        if [[ -s "${stderr_file}" ]]; then
            cat "${stderr_file}" >&2
        fi
        die "openssl command failed"
    fi
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

cleanup() {
    if [[ -n "${TEMPORARY_DIRECTORY}" ]]; then
        rm -rf -- "${TEMPORARY_DIRECTORY}"
    fi
}

validate_positive_integer() {
    [[ "$1" =~ ^[1-9][0-9]*$ ]] || die "invalid validity period '$1'"
}

validate_common_name() {
    [[ "$1" =~ ^[A-Za-z0-9._\ -]+$ ]] || die "invalid common name '$1'"
}

append_san() {
    case "$1" in
        DNS:*)
            [[ "${1#DNS:}" =~ ^[A-Za-z0-9.*_-]+$ ]] ||
                die "invalid DNS subject alternative name '$1'"
            ;;
        IP:*)
            [[ "${1#IP:}" =~ ^[0-9A-Fa-f:.]+$ ]] ||
                die "invalid IP subject alternative name '$1'"
            ;;
        *)
            die "invalid subject alternative name '$1'; use DNS:name or IP:address"
            ;;
    esac
    SUBJECT_ALTERNATIVE_NAMES+=("$1")
}

parse_args() {
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            -o | --output-dir)
                [[ "$#" -ge 2 ]] || die "$1 requires a value"
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --common-name)
                [[ "$#" -ge 2 ]] || die "$1 requires a value"
                COMMON_NAME="$2"
                shift 2
                ;;
            --san)
                [[ "$#" -ge 2 ]] || die "$1 requires a value"
                append_san "$2"
                shift 2
                ;;
            --days)
                [[ "$#" -ge 2 ]] || die "$1 requires a value"
                DAYS="$2"
                shift 2
                ;;
            -f | --force)
                FORCE=1
                shift
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                die "unknown argument '$1'; use --help for usage"
                ;;
        esac
    done
}

write_server_extensions() {
    local extension_file="$1"
    local index
    local san
    local delimiter=""

    {
        printf '%s\n' 'basicConstraints = critical, CA:FALSE'
        printf '%s\n' 'keyUsage = critical, digitalSignature, keyEncipherment'
        printf '%s\n' 'extendedKeyUsage = serverAuth'
        printf 'subjectAltName = '
        for san in "${SUBJECT_ALTERNATIVE_NAMES[@]}"; do
            printf '%s%s' "${delimiter}" "${san}"
            delimiter=","
        done
        printf '\n'
    } > "${extension_file}"

    for index in "${!SUBJECT_ALTERNATIVE_NAMES[@]}"; do
        log "SAN $((index + 1)): ${SUBJECT_ALTERNATIVE_NAMES[$index]}"
    done
}

main() {
    local ca_cert
    local ca_key
    local proxy_cert
    local proxy_key
    local csr
    local extension_file
    local output

    parse_args "$@"
    require_command openssl
    require_command mktemp
    validate_positive_integer "${DAYS}"
    validate_common_name "${COMMON_NAME}"

    mkdir -p "${OUTPUT_DIR}"
    OUTPUT_DIR="$(cd -- "${OUTPUT_DIR}" && pwd -P)"
    ca_cert="${OUTPUT_DIR}/proxlet-ca.pem"
    ca_key="${OUTPUT_DIR}/proxlet-ca-key.pem"
    proxy_cert="${OUTPUT_DIR}/proxlet-cert.pem"
    proxy_key="${OUTPUT_DIR}/proxlet-key.pem"

    for output in "${ca_cert}" "${ca_key}" "${proxy_cert}" "${proxy_key}"; do
        if [[ -e "${output}" && "${FORCE}" -ne 1 ]]; then
            die "file already exists: ${output}; use --force to replace generated files"
        fi
    done

    TEMPORARY_DIRECTORY="$(mktemp -d "${OUTPUT_DIR}/.create-cert-key.XXXXXX")"
    trap cleanup EXIT
    csr="${TEMPORARY_DIRECTORY}/proxlet.csr"
    extension_file="${TEMPORARY_DIRECTORY}/proxlet.ext"

    umask 077
    log "generating local CA"
    run_openssl openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "${ca_key}"
    run_openssl openssl req -x509 -new -sha256 \
        -key "${ca_key}" \
        -out "${ca_cert}" \
        -days "${DAYS}" \
        -subj "/CN=proxlet Local CA" \
        -addext "basicConstraints = critical, CA:TRUE" \
        -addext "keyUsage = critical, keyCertSign, cRLSign"

    log "generating HTTPS proxy certificate for CN=${COMMON_NAME}"
    run_openssl openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "${proxy_key}"
    run_openssl openssl req -new -sha256 \
        -key "${proxy_key}" \
        -out "${csr}" \
        -subj "/CN=${COMMON_NAME}"
    write_server_extensions "${extension_file}"
    run_openssl openssl x509 -req -sha256 \
        -in "${csr}" \
        -CA "${ca_cert}" \
        -CAkey "${ca_key}" \
        -CAcreateserial \
        -out "${proxy_cert}" \
        -days "${DAYS}" \
        -extfile "${extension_file}"
    rm -f -- "${OUTPUT_DIR}/proxlet-ca.srl"

    chmod 600 "${ca_key}" "${proxy_key}"
    chmod 644 "${ca_cert}" "${proxy_cert}"
    openssl verify -CAfile "${ca_cert}" "${proxy_cert}" >/dev/null

    log "generated files:"
    printf '  CA certificate:    %s\n' "${ca_cert}"
    printf '  CA private key:    %s\n' "${ca_key}"
    printf '  Proxy certificate: %s\n' "${proxy_cert}"
    printf '  Proxy private key: %s\n' "${proxy_key}"
    printf '\nStart an HTTPS proxy with:\n'
    printf "  proxlet --type https --tls-cert '%s' --tls-key '%s'\n" \
        "${proxy_cert}" "${proxy_key}"
    printf '\nDistribute only the CA certificate to clients:\n'
    printf '  %s\n' "${ca_cert}"
    printf 'Do not distribute %s or the whole output directory.\n' "${ca_key}"
}

main "$@"
