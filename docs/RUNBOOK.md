# Runbook

Every alert Crateward can send, what it means, what the automation already
did, and what to do. The list matches `crateward_core::escalation`
exactly. An alert that is not listed here is a bug.

Alerts arrive through ntfy with minimal text. Details are on the dashboard,
behind SSH.

## Stage failing after retries

**Meaning.** A stage's circuit breaker opened: infrastructure failures kept
happening after retries. Only that stage is paused. The others keep draining
their queues.

**Already done.** Jobs of the stage were put back with backoff. None were
failed for an infrastructure problem.

**What to do.**
1. Open the Operations page and read the last errors of the stage.
2. Fetch stage: check whether crates.io is reachable and whether responses
   are 429 or 5xx. Check the nftables allowlist sets for the fetcher user.
3. Sandbox stage: check `journalctl -u crateward-orchestrator` and the KVM
   section below.
4. Fix the cause. The breaker probes again by itself after its cooldown.
   To resume at once, run `crateward breaker close <stage>`. A closed
   breaker counts only failures after it closed, so the failures before
   the fix do not open it again. Queued jobs resume by priority.

## Disk usage above threshold

**Meaning.** A filesystem passed `storage.disk_alert_percent` (85 by default).

**Already done.** Retention jobs ran. If the scratch tmpfs is the one
filling, the sandbox stage stops claiming jobs.

**What to do.**
1. `df -h / /run/crateward` shows which filesystem is affected.
2. `du -sh` on the directories in the storage layout of
   [OPERATIONS.md](OPERATIONS.md) shows the component that grew.
3. Shorten `storage.raw_log_retention_days` or prune the image archive to
   the last two promoted versions.

## KVM error

**Meaning.** The kernel log or a Firecracker process reported a KVM error.

**Already done.** The sandbox stage breaker opened. No new VMs start.

**What to do.**
1. `journalctl -k | grep -i kvm` for the kernel side.
2. Check `/sys/devices/system/cpu/vulnerabilities/*` and the microcode
   version (`grep microcode /proc/cpuinfo`). A kernel or microcode update may
   have changed behavior.
3. Run the soak test (`cargo xtask soak`) against the current kernel. If it fails, boot the
   previous kernel from GRUB and pin it until a fix exists.

## Canary failure

**Meaning.** The known good canary was flagged, or the known bad canary was
not. Verdicts cannot be trusted.

**Already done.** The sandbox, analysis and finalize stages paused. Fetch
and static analysis continue. The pause lifts by itself once both canaries
pass again (they run every `sandbox.canary_interval_minutes`).

**What to do.**
1. Compare the canary run with the last passing run on the Operations page.
2. If a deploy just changed the guest version, roll it back:
   `./install.sh rollback` in the bundle that was installed, as root
   ([ADR 0002](adr/0002-firecracker-rootless-jail.md)). The
   orchestrator restarts on the previous version and runs the canaries
   first.
3. If the rollback restored passing canaries, investigate the new image
   offline before the next refresh.
4. If the canaries still fail on the old image, suspect the host (kernel
   update, disk, memory) and check the other alerts.

## High risk verdict

**Meaning.** A verdict needs human review. It is in the "needs you" inbox.
The job page links each piece of static evidence to its line on crates.io.
`crateward evidence <job> --out <dir>` writes its evidence pack.

**Already done.** Nothing was published. The verdict stays private.

**What to do.** Follow [DISCLOSURE.md](DISCLOSURE.md). A confirmed verdict
stays in the inbox, under "Confirmed, not reported", until
`crateward disclosure report` records its report. The job list filters for
it too.

## Sandbox escape indicator

**Meaning.** Something suggests a crate may have escaped its microVM:
Firecracker exited after a forbidden system call or a fatal signal,
something read the decoy in a jail root (the job ends as a suspected
compromise), something opened a decoy on the host, a process runs with a
slot UID that the jail did not start, or a file of the integrity manifest
changed ([ADR 0008](adr/0008-autonomy-and-escape-detection.md)). The
pause detail in `crateward status` lists the findings. A guest that merely
stopped itself is not an escape indicator. It is recorded as a result.

**Already done.** Quarantine: the whole pipeline paused. The job that was
running is failed and will not be retried automatically.

**What to do.**
1. Do not reboot yet. Volatile evidence lives in tmpfs.
2. Copy the jail directory of the slot, the tap capture and the job's
   evidence pack to the disk archive.
3. Check the host for persistence: new users, systemd units, cron entries,
   changed binaries (`crateward integrity --config <file> check`), unknown
   processes (`ps -eo pid,ppid,uid,comm` for the slot UIDs).
   An integrity finding right after a deploy usually means the manifest was
   not recorded again. Confirm the deploy changed exactly those files.
4. If anything is confirmed, treat the host as compromised: rotate the
   SSH keys, the deploy key and the ntfy topic,
   then reinstall from the Ansible playbooks and restore data from backup.
5. Report a Firecracker or KVM escape to the respective project's security
   contact.
6. Before lifting, run `crateward integrity --config <file> record` if the
   manifest was the cause and the new files are the deployed ones.
   Otherwise the next check quarantines the pipeline again.
7. Lift quarantine only after the cause is understood:
   `crateward quarantine lift`. `crateward status` shows what is paused.

## Decommissioning the server

The disks are not encrypted (ADR 0003), so before the server is cancelled
or a disk is replaced:

1. Revoke the GitHub deploy key and the read token, and rotate the ntfy
   topic.
2. Boot a rescue system and overwrite all disks completely, for
   example with `blkdiscard` where supported, otherwise `shred -n 1`.
