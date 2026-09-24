# Runbook

Every alert Crateward can send, what it means, what the automation already
did, and what to do. The list matches `crateward_core::escalation`
exactly; an alert that is not listed here is a bug.

Alerts arrive through ntfy with minimal text. Details are on the dashboard
behind WireGuard. Milestone markers show when a step becomes available.

## Stage failing after retries

**Meaning.** A stage's circuit breaker opened: infrastructure failures kept
happening after retries. Only that stage is paused; the others keep draining
their queues.

**Already done.** Jobs of the stage were put back with backoff; none were
failed for an infrastructure problem.

**What to do.**
1. Open the Operations page and read the last errors of the stage.
2. Fetch stage: check whether crates.io is reachable and whether responses
   are 429 or 5xx. Check the nftables allowlist sets for the fetcher user.
3. Sandbox stage: check `journalctl -u crateward-orchestrator` and the KVM
   section below.
4. Fix the cause, then close the breaker from the dashboard (M5). Queued
   jobs resume by priority.

## Disk usage above threshold

**Meaning.** A filesystem passed `storage.disk_alert_percent` (85 by default).

**Already done.** Retention jobs ran. If the scratch tmpfs is the one
filling, the sandbox stage stops claiming jobs.

**What to do.**
1. `df -h / /run/crateward` shows which filesystem is affected.
2. Check the storage budget table in [OPERATIONS.md](OPERATIONS.md) for the
   component that grew.
3. Shorten `storage.raw_log_retention_days` or prune the image archive to
   the last two promoted versions.

## KVM error

**Meaning.** The kernel log or a Firecracker process reported a KVM error.

**Already done.** The sandbox stage breaker opened; no new VMs start.

**What to do.**
1. `journalctl -k | grep -i kvm` for the kernel side.
2. Check `/sys/devices/system/cpu/vulnerabilities/*` and the microcode
   version (`grep microcode /proc/cpuinfo`); a kernel or microcode update may
   have changed behavior.
3. Run the soak test (M1) against the current kernel. If it fails, boot the
   previous kernel from GRUB and pin it until a fix exists.

## Canary failure

**Meaning.** The known good canary was flagged, or the known bad canary was
not. Verdicts cannot be trusted.

**Already done.** The pipeline paused. If an image refresh was being
promoted, it was rolled back automatically.

**What to do.**
1. Compare the canary run with the last passing run on the Operations page.
2. If the rollback restored passing canaries, investigate the new image
   offline before the next weekly refresh.
3. If the canaries still fail on the old image, suspect the host (kernel
   update, disk, memory) and check the other alerts.

## High risk verdict

**Meaning.** A verdict needs human review. It is in the "needs you" inbox
with an evidence pack.

**Already done.** Nothing was published. The verdict stays private.

**What to do.** Follow [DISCLOSURE.md](DISCLOSURE.md).

## Sandbox escape indicator

**Meaning.** Something suggests a crate may have escaped its microVM:
an unexpected VM exit, a Firecracker crash or seccomp violation, a host
honeytoken touched, or unexpected changes on the host.

**Already done.** Quarantine: the whole pipeline paused. The job that was
running is failed and will not be retried automatically.

**What to do.**
1. Do not reboot yet; volatile evidence lives in tmpfs.
2. Copy the jail directory of the slot, the tap capture and the job's
   evidence pack to the HDD archive.
3. Check the host for persistence: new users, systemd units, cron entries,
   changed binaries (integrity monitoring, M7), unknown processes.
4. If anything is confirmed, treat the host as compromised: rotate the
   WireGuard keys, the deploy key, the ntfy topic and the heartbeat URL,
   then reinstall from the Ansible playbooks and restore data from backup.
5. Report a Firecracker or KVM escape to the respective project's security
   contact.
6. Lift quarantine from the CLI only after the cause is understood (M5).

## Decommissioning the server

The disks are not encrypted (ADR 0013), so before the server is cancelled
or a disk is replaced:

1. Revoke the GitHub deploy key and the read token, and rotate the ntfy
   topic and the healthchecks.io ping URL.
2. Boot the Hetzner rescue system and overwrite both disks completely, for
   example with `blkdiscard` where supported, otherwise `shred -n 1`.

## Heartbeat lost

**Meaning.** healthchecks.io did not receive a ping in time. The server is
down, cannot reach the internet, or the supervisor stopped. This alert is
sent by healthchecks.io, not by Crateward.

**What to do.**
1. Try WireGuard and SSH.
2. If unreachable, check the Hetzner Robot panel for the server status and
   use the rescue system or a KVM console request if needed.
3. After a reboot the encrypted disks need unlocking (procedure in M8).
