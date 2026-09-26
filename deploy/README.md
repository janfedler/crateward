# Deployment

Everything a fresh Debian 13 server needs to run Crateward. The maintainer
applies it as root; nothing here runs automatically.

| Path | What |
|------|------|
| `ansible/rollback.yml` | Switches the guest files back to the previous version and restarts the orchestrator ([ADR 0024](../docs/adr/0024-guest-image-versions-and-rollback.md)) |
| `ansible/site.yml` | The whole host: kernel command line, swap and KSM, packages, users, directories, the sandbox tmpfs, PostgreSQL with data checksums, the release bundle, the configuration, WireGuard, SSH, the firewall, the units, the integrity manifest |
| `ansible/vars.example.yml` | Every variable of the playbook |
| `systemd/` | One hardened unit per component, the egress refresh and the daily database dump |
| `nftables/crateward.nft` | Inbound: WireGuard and SSH only. Outbound: each service user reaches its allowlisted hosts and nothing else |

## First setup

1. Build the release bundle on a development machine:
   `cargo xtask release` (see TESTING.md for what to run before).
2. Copy `ansible/vars.example.yml` and `ansible/inventory.example.yml`
   outside the repository and fill them in. The configuration file starts
   from `config/crateward.example.toml` and holds the secrets.
3. Run the playbook:
   `ansible-playbook -i inventory.yml deploy/ansible/site.yml -e @vars.yml`.
   It needs only `ansible-core`.
4. Reboot once, so the kernel command line applies. Then check the host
   with [the security checklist](../docs/SECURITY_CHECKLIST.md).
5. Set up WireGuard (`wireguard_private_key_file` and the peer), log in
   through the tunnel, then set `ssh_wireguard_only: true` and run the
   playbook again. Until then SSH stays reachable on the public
   interface, so a broken tunnel cannot lock you out.

## Every deploy

Run the playbook with the new bundle. It restarts the services whose
binaries or configuration changed; `systemctl restart` waits until the
orchestrator has drained its jobs. The playbook records the integrity
manifest after installing, so the supervisor does not quarantine the
pipeline for the new binaries.

## Rolling back the guest

The guest kernel, root filesystem and authority are installed per version
under `/usr/local/lib/crateward/guest/`, with `current` and `previous`
links. After a deploy, the orchestrator runs the canaries before any job.
If they fail, the pipeline pauses and the alert says so; then run
`ansible-playbook -i inventory.yml deploy/ansible/rollback.yml`.

## What the playbook cannot know

* The decoys in `supervisor.decoys` must be excluded from backups and
  indexers.
* The offsite backup target is not chosen yet; the daily dump lands in
  `/var/backups/crateward` only.
* The firewall allowlist follows the configuration. A new external service
  needs its host in the configuration, or for the image builder in
  `crates/cli/src/egress.rs`.
