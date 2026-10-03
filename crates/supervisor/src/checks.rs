//! Decisions of the supervisor that need no I/O, so they can be tested.

/// Percent of a filesystem in use, rounded up, from `statvfs` numbers:
/// blocks in total, free blocks, and blocks available to unprivileged users.
/// Blocks reserved for root count as used, as `df` does.
#[must_use]
pub fn used_percent(total: u64, free: u64, available: u64) -> u8 {
    let used = total.saturating_sub(free);
    let usable = used.saturating_add(available);
    if usable == 0 {
        return 0;
    }

    let percent = (u128::from(used) * 100).div_ceil(u128::from(usable));
    u8::try_from(percent.min(100)).unwrap_or(100)
}

/// What to do about the canaries, from the latest result of each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryAction {
    /// No results yet: leave everything as it is.
    Wait,
    /// Every canary passed: lift a canary pause.
    AllPassed,
    /// These canaries gave the wrong result: pause and alert.
    Failed(Vec<String>),
}

/// Decides from `(name, passed, when)` for the latest run of each canary.
#[must_use]
pub fn canary_action(latest: &[(String, bool, i64)]) -> CanaryAction {
    if latest.is_empty() {
        return CanaryAction::Wait;
    }

    let failed: Vec<String> = latest
        .iter()
        .filter(|(_, passed, _)| !passed)
        .map(|(name, _, _)| name.clone())
        .collect();
    if failed.is_empty() {
        CanaryAction::AllPassed
    } else {
        CanaryAction::Failed(failed)
    }
}

/// Whether an alert is sent again, given when the same alert last went out.
#[must_use]
pub fn should_send(seconds_since_sent: Option<i64>, repeat_hours: u64) -> bool {
    let repeat = i64::try_from(repeat_hours.saturating_mul(3600)).unwrap_or(i64::MAX);
    seconds_since_sent.is_none_or(|since| since >= repeat)
}

/// A process on the host, from `/proc/<pid>/status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProcess {
    /// Process ID.
    pub pid: i32,
    /// Parent process ID.
    pub ppid: i32,
    /// Real, effective, saved and file system UIDs.
    pub uids: [u32; 4],
    /// The name the kernel reports (at most 15 bytes).
    pub name: String,
}

/// Process IDs that run as a slot UID without being what the jail starts
/// (ADR 0008). A slot runs exactly one `firecracker`, started by a process
/// outside the slot range, and at most one `fake-internet` below it, with
/// the same UID. Anything else has no business running as a slot UID: the
/// jail launcher itself has that name only for the moment before it
/// executes Firecracker, so the supervisor reports a process only when two
/// scans in a row find it.
#[must_use]
pub fn stray_processes(
    processes: &[HostProcess],
    slot_uids: std::ops::RangeInclusive<u32>,
) -> Vec<i32> {
    let slot_uid = |p: &HostProcess| p.uids.iter().copied().find(|u| slot_uids.contains(u));
    let by_pid: std::collections::HashMap<i32, &HostProcess> =
        processes.iter().map(|p| (p.pid, p)).collect();
    let mut firecrackers: std::collections::HashMap<u32, Vec<i32>> =
        std::collections::HashMap::new();
    let mut sinks: std::collections::HashMap<u32, Vec<i32>> = std::collections::HashMap::new();
    let mut stray = Vec::new();

    for p in processes {
        let Some(uid) = slot_uid(p) else { continue };
        let uniform = p.uids.iter().all(|u| *u == uid);
        let parent = by_pid.get(&p.ppid);
        let ok = uniform
            && match p.name.as_str() {
                "firecracker" => {
                    let outside = parent.is_some_and(|q| slot_uid(q).is_none());
                    outside && {
                        firecrackers.entry(uid).or_default().push(p.pid);
                        true
                    }
                }
                "fake-internet" => {
                    let below = parent.is_some_and(|q| {
                        q.name == "firecracker" && q.uids.iter().all(|u| *u == uid)
                    });

                    below && {
                        sinks.entry(uid).or_default().push(p.pid);
                        true
                    }
                }
                _ => false,
            };
        if !ok {
            stray.push(p.pid);
        }
    }

    for pids in firecrackers.values().chain(sinks.values()) {
        if pids.len() > 1 {
            stray.extend(pids);
        }
    }

    stray.sort_unstable();
    stray.dedup();
    stray
}

/// Parses `/proc/<pid>/status`.
#[must_use]
pub fn parse_status(pid: i32, text: &str) -> Option<HostProcess> {
    let mut name = None;
    let mut ppid = None;
    let mut uids = None;

    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };

        let value = value.trim();
        match key {
            "Name" => name = Some(value.to_owned()),
            "PPid" => ppid = value.parse().ok(),
            "Uid" => {
                let parsed: Vec<u32> = value
                    .split_whitespace()
                    .filter_map(|u| u.parse().ok())
                    .collect();
                uids = <[u32; 4]>::try_from(parsed).ok();
            }
            _ => {}
        }
    }

    Some(HostProcess {
        pid,
        ppid: ppid?,
        uids: uids?,
        name: name?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: i32, ppid: i32, uid: u32, name: &str) -> HostProcess {
        HostProcess {
            pid,
            ppid,
            uids: [uid; 4],
            name: name.to_owned(),
        }
    }

    #[test]
    fn only_what_the_jail_starts_may_run_as_a_slot() {
        let slots = 160_010..=160_013;
        let mut procs = vec![
            process(1, 0, 0, "systemd"),
            process(10, 1, 1000, "crateward-orche"),
            process(20, 10, 160_010, "firecracker"),
            process(21, 20, 160_010, "fake-internet"),
            process(30, 10, 160_011, "firecracker"),
        ];

        assert!(stray_processes(&procs, slots.clone()).is_empty());

        // A shell below Firecracker, a second Firecracker of the same
        // slot, and a Firecracker started from inside a slot.
        procs.push(process(40, 20, 160_010, "sh"));
        procs.push(process(41, 10, 160_011, "firecracker"));
        procs.push(process(42, 21, 160_012, "firecracker"));

        assert_eq!(stray_processes(&procs, slots.clone()), vec![30, 40, 41, 42]);

        // Mixed UIDs, for example after a setuid binary.
        let mut mixed = process(50, 10, 160_013, "firecracker");
        mixed.uids[1] = 0;

        assert_eq!(stray_processes(&[mixed], slots), vec![50]);
    }

    #[test]
    fn status_files_parse() {
        let text = "Name:\tfake-internet\nUmask:\t0022\nState:\tS (sleeping)\nPPid:\t463533\n\
                    Uid:\t160012\t160012\t160012\t160012\nGid:\t1\t1\t1\t1\n";
        assert_eq!(
            parse_status(7, text),
            Some(process(7, 463_533, 160_012, "fake-internet"))
        );
        assert_eq!(parse_status(7, "Name:\tx\n"), None);
    }

    #[test]
    fn disk_usage_counts_reserved_blocks_as_used() {
        assert_eq!(used_percent(1000, 1000, 950), 0);

        // 500 used, 450 available to users (50 reserved): 500 / 950.
        assert_eq!(used_percent(1000, 500, 450), 53);
        assert_eq!(used_percent(1000, 0, 0), 100);
        assert_eq!(used_percent(0, 0, 0), 0);
    }

    #[test]
    fn canaries_pause_on_any_failure_and_lift_when_all_pass() {
        assert_eq!(canary_action(&[]), CanaryAction::Wait);

        let ok = ("canary-inert".to_owned(), true, 1);
        let bad = ("canary-exfil".to_owned(), false, 2);

        assert_eq!(
            canary_action(std::slice::from_ref(&ok)),
            CanaryAction::AllPassed
        );
        assert_eq!(
            canary_action(&[ok, bad]),
            CanaryAction::Failed(vec!["canary-exfil".into()])
        );
    }

    #[test]
    fn alerts_repeat_only_after_the_interval() {
        assert!(should_send(None, 24));
        assert!(!should_send(Some(3600), 24));
        assert!(should_send(Some(24 * 3600), 24));
    }
}
