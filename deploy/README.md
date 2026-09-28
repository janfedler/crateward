# Deployment

Everything a fresh Debian 13 server needs to run Crateward. The maintainer
applies it as root; nothing here runs automatically.

| Path | What |
|------|------|
| `install.sh` | Installs, updates or removes Crateward from an unpacked release bundle. It verifies the bundle, writes the configuration on the first run, installs `ansible-core` and runs the playbooks below on the server itself |
| `ansible/components.yml` | The service users, services and timers, shared by the playbooks |
| `ansible/rollback.yml` | Switches the guest files back to the previous version and restarts the orchestrator ([ADR 0024](../docs/adr/0024-guest-image-versions-and-rollback.md)) |
| `ansible/uninstall.yml` | Removes the software and keeps the state; with `purge=true` it removes the state too |
| `ansible/site.yml` | The whole host: kernel command line, swap and KSM, packages, users, directories, the sandbox tmpfs, PostgreSQL with data checksums, the release bundle, the configuration, WireGuard, SSH, the firewall, the units, the integrity manifest |
| `ansible/vars.example.yml` | Every variable of the playbook |
| `systemd/` | One hardened unit per component, the egress refresh and the daily database dump |
| `nftables/crateward.nft` | Inbound: WireGuard and SSH only. Outbound: each service user reaches its allowlisted hosts and nothing else |

## First setup

1. Build the release bundle: `cargo xtask release` (see TESTING.md for what
   to run before). It writes the bundle directory and its tarball to
   `target/release-bundle/`.
2. Sign it: `ssh-keygen -Y sign -f <release key> -n file SHA256SUMS` in the
   bundle directory, then `cargo xtask pack <bundle directory>` to pack the
   signature into the tarball.
3. As root on the server, prepare `/root/crateward` (mode 0700):
   * `allowed_signers` with one line, `crateward-release <release public key>`;
   * `site-deploy-key`, the site repository's deploy key, if it exists yet.
4. Unpack the tarball anywhere and run `./install.sh` from it. The first
   run asks for the ntfy topic, the healthchecks.io ping URL and the
   dashboard address, and writes `/root/crateward/crateward.toml` and
   `/root/crateward/vars.yml`. It refuses to run while another
   orchestrator runs on the host, such as a development pipeline.
5. Reboot once, so the kernel command line applies. Then check the host
   with [the security checklist](../docs/SECURITY_CHECKLIST.md).
6. Set up WireGuard in `/root/crateward/vars.yml`
   (`wireguard_private_key_file` and the peer), run `./install.sh` again,
   and log in through the tunnel. Then set `ssh_wireguard_only: true` and
   run it once more. Until then SSH stays reachable on the public
   interface, so a broken tunnel cannot lock you out.

`install.sh` checks `SHA256SUMS` and its signature, but a script cannot
vouch for itself. For a bundle copied from another machine, check the
signature before running anything from it:

```sh
ssh-keygen -Y verify -f /root/crateward/allowed_signers -I crateward-release \
    -n file -s SHA256SUMS.sig < SHA256SUMS && sha256sum --check SHA256SUMS
```

`./install.sh --unsigned` installs a bundle without a signature.

## Every deploy

Unpack the new bundle and run `./install.sh` from it. It keeps the
configuration and the variables in `/root/crateward` and restarts the
services whose binaries or configuration changed; `systemctl restart`
waits until the orchestrator has drained its jobs. The playbook records the
integrity manifest after installing, so the supervisor does not quarantine
the pipeline for the new binaries.

Without the script, the same deploy is
`ansible-playbook -i inventory.yml deploy/ansible/site.yml -e @vars.yml`,
with `crateward_release_dir` and `crateward_config_file` set in
`vars.yml`. It needs only `ansible-core`.

## Removing it

`./install.sh uninstall` stops the services and removes the software. The
configuration, the database, the evidence, the backups, the service users
and the firewall stay, so `./install.sh` brings it back as it was.

`./install.sh uninstall --purge` removes all of that too, after asking to
type `purge`. Both leave `/root/crateward`, SSH, WireGuard and the host
settings for the sandbox (kernel command line, swap, KSM) as they are.

## Rolling back the guest

The guest kernel, root filesystem and authority are installed per version
under `/usr/local/lib/crateward/guest/`, with `current` and `previous`
links. After a deploy, the orchestrator runs the canaries before any job.
If they fail, the pipeline pauses and the alert says so; then run
`./install.sh rollback` from the bundle. Running it again switches forward
again.

## What the playbook cannot know

* The decoys in `supervisor.decoys` must be excluded from backups and
  indexers.
* The offsite backup target is not chosen yet; the daily dump lands in
  `/var/backups/crateward` only.
* The firewall allowlist follows the configuration. A new external service
  needs its host in the configuration, or for the image builder in
  `crates/cli/src/egress.rs`.
