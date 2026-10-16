#!/usr/bin/env bash
# Installs, updates or removes Crateward on this server, from the release
# bundle this script is part of. Run it as root from the unpacked bundle:
#
#   ./install.sh                     install, or update to this bundle
#   ./install.sh rollback            switch the guest back to the previous version
#   ./install.sh uninstall           remove the software, keep all state
#   ./install.sh uninstall --purge   remove the state as well
#
# The first install asks for the operator's contact details, the ntfy topic,
# the site repository, whether every export refreshes the published job
# reports, and the dashboard address, and writes the configuration. Without
# a terminal it reads CRATEWARD_CONTACT_URL, CRATEWARD_CONTACT_EMAIL,
# CRATEWARD_NTFY_TOPIC, CRATEWARD_SITE_REPOSITORY ("none" for no public
# site), CRATEWARD_SITE_REPORTS ("yes" or "no", only with a site) and
# CRATEWARD_WEB_LISTEN instead.
#
# Everything the maintainer owns stays in CRATEWARD_STATE (default
# /root/crateward), mode 0700:
#
#   crateward.toml    the configuration, written on the first install
#   vars.yml          the playbook variables, written on the first install
#   site-deploy-key   the site repository's deploy key, if present
#   allowed_signers   the release signing key, for `ssh-keygen -Y verify`
#   ansible/          ansible-core, from the hash pinned requirements
#
# The work itself is done by deploy/ansible/site.yml and uninstall.yml. This
# script only prepares their inputs. A script cannot vouch for itself: for a
# bundle that came from another machine, check the signature by hand before
# running it (docs/OPERATIONS.md, "Deploying a new build").

set -euo pipefail
umask 077

BUNDLE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
STATE="${CRATEWARD_STATE:-/root/crateward}"

die() {
    echo "install.sh: $*" >&2
    exit 1
}

say() {
    echo "install.sh: $*" >&2
}

usage() {
    sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

preflight() {
    [[ "$(id -u)" == 0 ]] || die "run this as root"
    # shellcheck source=/dev/null
    . /etc/os-release
    [[ "${ID:-}" == debian && "${VERSION_ID:-}" == 13 ]] || die "only Debian 13 is supported"
    # Ansible splits key=value arguments at spaces.
    [[ "$BUNDLE$STATE" != *[[:space:]]* ]] || die "the paths must not contain spaces"
    mkdir -p "$STATE"
    chmod 0700 "$STATE"
}

# The files of the bundle match SHA256SUMS, and SHA256SUMS carries a valid
# signature by a key in allowed_signers, unless --unsigned was given.
verify_bundle() {
    local unsigned="$1"
    (cd "$BUNDLE" && sha256sum --quiet --strict --check SHA256SUMS) ||
        die "the bundle does not match SHA256SUMS"
    local signature="$BUNDLE/SHA256SUMS.sig"
    if [[ ! -f "$signature" ]]; then
        [[ "$unsigned" == yes ]] ||
            die "no SHA256SUMS.sig in the bundle; sign SHA256SUMS or pass --unsigned"
        say "installing an unsigned bundle, as asked"
        return
    fi
    local signers="$STATE/allowed_signers"
    [[ -f "$signers" ]] ||
        die "no $signers; add a line: crateward-release <the release public key>"
    local principal
    principal="$(ssh-keygen -Y find-principals -f "$signers" -s "$signature" | head -n 1)" ||
        die "SHA256SUMS.sig is not from a key in $signers"
    ssh-keygen -Y verify -f "$signers" -I "$principal" -n file -s "$signature" \
        < "$BUNDLE/SHA256SUMS" > /dev/null ||
        die "the signature over SHA256SUMS does not verify"
    say "the bundle is signed by $principal"
}

# Another orchestrator on this host, such as one from a source checkout,
# would compete for KVM, the slot UIDs and the tmpfs.
no_foreign_orchestrator() {
    local foreign
    foreign="$(ps -eo user:32=,comm= |
        awk '$2 ~ /^crateward_orche/ && $1 != "crateward-orchestrator" { print $1 }' |
        sort -u | tr '\n' ' ')"
    [[ -z "$foreign" ]] ||
        die "an orchestrator runs as ${foreign% }; stop it before installing"
}

ask() {
    local variable="$1" prompt="$2" default="$3" value="${!1:-}"
    if [[ -z "$value" ]]; then
        [[ -t 0 ]] || die "no terminal; set $variable"
        read -r -p "$prompt${default:+ [$default]}: " value
        value="${value:-$default}"
    fi
    printf '%s' "$value"
}

# The dashboard listens where the SSH tunnel can reach it: on the IPv6
# loopback when sshd only speaks IPv6.
default_listen() {
    if sshd -T 2> /dev/null | grep -qx 'addressfamily inet6'; then
        echo '[::1]:8080'
    else
        echo '127.0.0.1:8080'
    fi
}

# Copies standard input without the TOML table named $1.
without_table() {
    awk -v table="[$1]" '$0 == table { skip = 1; next } /^\[/ { skip = 0 } !skip'
}

write_config() {
    local config="$STATE/crateward.toml"
    if [[ -f "$config" ]]; then
        say "keeping $config"
        return
    fi
    local url email topic repository listen
    # Characters that would break the user agent, the TOML string or sed.
    local unsafe='[[:space:]";|&)\\]'
    # crates.io asks for a user agent that names a way to reach the operator.
    url="$(ask CRATEWARD_CONTACT_URL "operator website, sent in the user agent" "")"
    [[ "$url" == https://?* && ! "$url" =~ $unsafe ]] || die "the website must be an https:// URL"
    email="$(ask CRATEWARD_CONTACT_EMAIL "operator email address, sent in the user agent and shown on the public site" "")"
    [[ "$email" == ?*@?* && ! "$email" =~ $unsafe ]] || die "not an email address"
    topic="$(ask CRATEWARD_NTFY_TOPIC "ntfy topic (openssl rand -hex 24)" "")"
    [[ "$topic" =~ ^[A-Za-z0-9_-]{32,64}$ && "$topic" != example_* ]] ||
        die "the ntfy topic must be 32 to 64 characters of [A-Za-z0-9_-]"
    repository="$(ask CRATEWARD_SITE_REPOSITORY "site repository, git@github.com:owner/name.git, or none" "none")"
    [[ "$repository" == none || "$repository" =~ ^git@github\.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git$ ]] ||
        die "the site repository must be git@github.com:owner/name.git or none"
    # The job reports `crateward archive --publish` put on the site.
    local reports=false
    if [[ "$repository" != none ]]; then
        case "$(ask CRATEWARD_SITE_REPORTS "refresh the published job reports with every export, yes or no" "no")" in
            yes) reports=true ;;
            no) ;;
            *) die "answer yes or no" ;;
        esac
    fi
    listen="$(ask CRATEWARD_WEB_LISTEN "dashboard address, loopback only" "$(default_listen)")"
    [[ "$listen" =~ ^(127\.0\.0\.1|\[::1\]):[0-9]{1,5}$ ]] ||
        die "the dashboard address must be 127.0.0.1:<port> or [::1]:<port>"

    local draft="$STATE/crateward.toml.new"
    sed -e "s|^contact_email = .*|contact_email = \"$email\"|" \
        -e "s|^user_agent = .*|user_agent = \"crateward/0.1 (+$url; $email)\"|" \
        -e "s|^topic = .*|topic = \"$topic\"|" \
        -e "s|^repository = .*|repository = \"$repository\"|" \
        -e "s|^reports = .*|reports = $reports|" \
        -e "s|^listen = .*|listen = \"$listen\"|" \
        "$BUNDLE/config/crateward.example.toml" |
        if [[ "$repository" == none ]]; then without_table export; else cat; fi > "$draft"
    "$BUNDLE/bin/crateward" config check --config "$draft" ||
        die "the configuration does not validate; see $draft"
    mv "$draft" "$config"
    say "wrote $config"
}

write_vars() {
    local vars="$STATE/vars.yml"
    if [[ -f "$vars" ]]; then
        say "keeping $vars"
        return
    fi
    cp "$BUNDLE/deploy/ansible/vars.example.yml" "$vars"
    say "wrote $vars"
}

# ansible-core in a virtual environment, reinstalled when the pinned
# requirements change.
ensure_ansible() {
    local venv="$STATE/ansible" requirements="$BUNDLE/deploy/ansible/requirements.txt"
    local stamp="$venv/requirements.sha256" want
    want="$(sha256sum < "$requirements")"
    if [[ -x "$venv/bin/ansible-playbook" && -f "$stamp" && "$(cat "$stamp")" == "$want" ]]; then
        return
    fi
    if ! dpkg-query --show --showformat='${Status}' python3-venv 2> /dev/null |
        grep -q 'install ok installed'; then
        say "installing python3-venv"
        apt-get update --quiet
        apt-get install --yes --quiet python3-venv
    fi
    say "installing ansible-core into $venv"
    rm -rf "$venv"
    python3 -m venv "$venv"
    "$venv/bin/pip" install --quiet --require-hashes --requirement "$requirements"
    printf '%s' "$want" > "$stamp"
}

# Runs a playbook of the bundle against this machine.
playbook() {
    local inventory status=0
    # The YAML inventory plugin only reads files ending in .yml.
    inventory="$(mktemp --suffix=.yml)"
    # The modules run with the system Python, which has python3-apt.
    cat > "$inventory" << 'EOF'
crateward:
  hosts:
    localhost:
      ansible_connection: local
      ansible_python_interpreter: /usr/bin/python3
EOF
    # ansible-core refuses to run without a UTF-8 locale. Facts are read
    # only through ansible_facts, as ansible-core 2.24 will require, so a
    # bare fact name fails here instead of in a later release.
    LC_ALL=C.UTF-8 ANSIBLE_INJECT_FACT_VARS=False \
        "$STATE/ansible/bin/ansible-playbook" -i "$inventory" "$@" || status=$?
    rm -f "$inventory"
    return "$status"
}

install() {
    local unsigned=no
    while (($#)); do
        case "$1" in
            --unsigned) unsigned=yes ;;
            -h | --help) usage ;;
            *) usage 2 ;;
        esac
        shift
    done
    preflight
    verify_bundle "$unsigned"
    no_foreign_orchestrator
    write_config
    write_vars
    ensure_ansible

    local extra=(
        -e "@$STATE/vars.yml"
        -e "crateward_release_dir=$BUNDLE"
        -e "crateward_config_file=$STATE/crateward.toml"
    )
    if [[ -f "$STATE/site-deploy-key" ]]; then
        extra+=(-e "site_deploy_key_file=$STATE/site-deploy-key")
    else
        say "no $STATE/site-deploy-key; the public export will fail until it is there"
    fi
    playbook "$BUNDLE/deploy/ansible/site.yml" "${extra[@]}"

    say "installed $(basename "$BUNDLE")"
    if ! grep -qw nosmt /proc/cmdline; then
        say "reboot once, so the kernel command line applies"
    fi
    say "check it with: systemctl status 'crateward-*'; crateward status"
}

uninstall() {
    local purge=false
    while (($#)); do
        case "$1" in
            --purge) purge=true ;;
            -h | --help) usage ;;
            *) usage 2 ;;
        esac
        shift
    done
    preflight
    if [[ "$purge" == true ]]; then
        [[ -t 0 ]] || die "--purge needs a terminal to confirm"
        local answer
        read -r -p "Delete the database, all evidence, the backups and the service users? Type purge: " answer
        [[ "$answer" == purge ]] || die "nothing removed"
    fi
    ensure_ansible
    local extra=(-e "purge=$purge")
    if [[ -f "$STATE/vars.yml" ]]; then
        extra=(-e "@$STATE/vars.yml" "${extra[@]}")
    fi
    playbook "$BUNDLE/deploy/ansible/uninstall.yml" "${extra[@]}"
    if [[ "$purge" == true ]]; then
        say "removed Crateward and its state; the host has no Crateward firewall rules now"
    else
        say "removed the software; the state is kept, and ./install.sh restores it"
    fi
    say "$STATE, SSH and the kernel command line are unchanged"
}

# Switches the guest files back to the previous version (ADR 0002,
# RUNBOOK.md "Canary failure").
rollback() {
    (($# == 0)) || usage 2
    preflight
    ensure_ansible
    playbook "$BUNDLE/deploy/ansible/rollback.yml"
}

main() {
    case "${1:-install}" in
        install) shift || true; install "$@" ;;
        rollback) shift; rollback "$@" ;;
        uninstall) shift; uninstall "$@" ;;
        -h | --help) usage ;;
        --*) install "$@" ;;
        *) usage 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
