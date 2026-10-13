//! Which jobs go into the archive: filters, a cap per level, and jobs
//! added or removed by hand. It is saved next to the archive, so the same
//! choice can be made again.

use std::collections::{BTreeSet, HashMap};

use crateward_core::store::ArchiveCandidate;
use serde::{Deserialize, Serialize};

/// Risk levels, severe first.
pub const LEVELS: [&str; 5] = ["critical", "high", "medium", "low", "none"];

/// Reviews the archive may show, and their labels. Pending reviews never
/// appear ([`ArchiveCandidate::refusal`]).
pub const REVIEWS: [(&str, &str); 3] = [
    ("none", "not reviewed"),
    ("false_positive", "false positive"),
    ("confirmed", "confirmed, published"),
];

/// Coverage kinds and their labels.
pub const COVERAGE: [(&str, &str); 3] = [
    ("dynamic_linux", "VM run"),
    ("static_only", "static only"),
    ("not_applicable_on_linux", "not for Linux"),
];

/// How the archive's jobs are chosen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Selection {
    /// Levels to take.
    pub levels: BTreeSet<String>,
    /// Reviews to take.
    pub reviews: BTreeSet<String>,
    /// Coverage kinds to take.
    pub coverage: BTreeSet<String>,
    /// The lowest score to take.
    pub min_score: i32,
    /// A crate name prefix, or empty for any.
    pub name: String,
    /// The most jobs per level, highest score first, or 0 for all.
    pub per_level: usize,
    /// Jobs taken whatever the filters say.
    pub include: BTreeSet<i64>,
    /// Jobs left out whatever the filters say.
    pub exclude: BTreeSet<i64>,
}

impl Default for Selection {
    fn default() -> Self {
        let set = |items: &[&str]| items.iter().map(|&s| s.to_owned()).collect();

        Self {
            levels: set(&["critical", "high", "medium"]),
            reviews: set(&REVIEWS.map(|(r, _)| r)),
            coverage: set(&COVERAGE.map(|(c, _)| c)),
            min_score: 0,
            name: String::new(),
            per_level: 25,
            include: BTreeSet::new(),
            exclude: BTreeSet::new(),
        }
    }
}

/// What the selection makes of a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// It must not be archived.
    Refused(&'static str),
    /// Taken by hand.
    Included,
    /// Taken by the filters.
    Chosen,
    /// Matches the filters, but its level has enough jobs.
    Capped,
    /// Left out by hand.
    Excluded,
    /// Does not match the filters.
    Filtered,
}

impl Mark {
    /// Whether the job goes into the archive.
    #[must_use]
    pub fn taken(self) -> bool {
        matches!(self, Self::Included | Self::Chosen)
    }
}

/// A name in canonical form: lowercase, `-` as `_`.
fn canonical(name: &str) -> String {
    name.to_ascii_lowercase().replace('-', "_")
}

impl Selection {
    /// Whether `c` passes the filters, before the cap.
    #[must_use]
    pub fn matches(&self, c: &ArchiveCandidate) -> bool {
        self.reviews.contains(&c.review) && self.matches_but_review(c)
    }

    /// Whether `c` passes every filter but the review's, which has no
    /// choice for the reviews the archive refuses.
    #[must_use]
    pub fn matches_but_review(&self, c: &ArchiveCandidate) -> bool {
        self.levels.contains(&c.level)
            && self.coverage.contains(&c.coverage)
            && c.score >= self.min_score
            && canonical(&c.name).starts_with(&canonical(&self.name))
    }

    /// The mark of every candidate, in their order. The cap takes the first
    /// matches of each level, so candidates come highest score first.
    #[must_use]
    pub fn marks(&self, candidates: &[ArchiveCandidate]) -> Vec<Mark> {
        let mut per_level: HashMap<&str, usize> = HashMap::new();

        candidates
            .iter()
            .map(|c| {
                if let Some(reason) = c.refusal() {
                    return Mark::Refused(reason);
                }

                if self.exclude.contains(&c.id.0) {
                    return Mark::Excluded;
                }

                if self.include.contains(&c.id.0) {
                    return Mark::Included;
                }

                if !self.matches(c) {
                    return Mark::Filtered;
                }

                let taken = per_level.entry(c.level.as_str()).or_default();
                if self.per_level > 0 && *taken >= self.per_level {
                    return Mark::Capped;
                }

                *taken += 1;
                Mark::Chosen
            })
            .collect()
    }

    /// The jobs to archive.
    #[must_use]
    pub fn chosen(&self, candidates: &[ArchiveCandidate]) -> Vec<i64> {
        candidates
            .iter()
            .zip(self.marks(candidates))
            .filter(|(_, m)| m.taken())
            .map(|(c, _)| c.id.0)
            .collect()
    }

    /// Takes a job that is not taken, or leaves out one that is. Refused
    /// jobs stay as they are.
    pub fn toggle(&mut self, id: i64, mark: Mark) {
        match mark {
            Mark::Refused(_) => {}
            Mark::Included => {
                self.include.remove(&id);
            }
            Mark::Chosen => {
                self.exclude.insert(id);
            }
            Mark::Excluded => {
                self.exclude.remove(&id);
            }
            Mark::Capped | Mark::Filtered => {
                self.include.insert(id);
            }
        }
    }

    /// Adds `item` to `set`, or removes it.
    pub fn flip(set: &mut BTreeSet<String>, item: &str) {
        if !set.remove(item) {
            set.insert(item.to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use crateward_core::job::JobId;

    use super::*;

    fn candidate(id: i64, name: &str, score: i32, level: &str, review: &str) -> ArchiveCandidate {
        ArchiveCandidate {
            id: JobId(id),
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            score,
            level: level.to_owned(),
            review: review.to_owned(),
            coverage: "dynamic_linux".to_owned(),
            published: id == 1,
            top_evidence: String::new(),
        }
    }

    fn candidates() -> Vec<ArchiveCandidate> {
        vec![
            candidate(1, "monica_rand_core", 95, "critical", "confirmed"),
            candidate(2, "secret-stash", 90, "critical", "confirmed"),
            candidate(3, "waiting", 80, "critical", "pending"),
            candidate(4, "cmake-sys", 60, "high", "false_positive"),
            candidate(5, "a-medium", 40, "medium", "none"),
            candidate(6, "b-medium", 35, "medium", "none"),
            candidate(7, "c-medium", 30, "medium", "none"),
            candidate(8, "quiet", 0, "none", "none"),
        ]
    }

    #[test]
    fn unpublished_and_unreviewed_findings_are_never_taken() {
        let mut selection = Selection::default();
        selection.include.extend([2, 3]);
        let marks = selection.marks(&candidates());

        assert_eq!(marks.first(), Some(&Mark::Chosen));
        assert_eq!(
            marks.get(1),
            Some(&Mark::Refused("confirmed, not published yet"))
        );
        assert_eq!(marks.get(2), Some(&Mark::Refused("waits for review")));
        assert_eq!(selection.chosen(&candidates()), [1, 4, 5, 6, 7]);
    }

    #[test]
    fn the_cap_takes_the_highest_scores_of_each_level() {
        let selection = Selection {
            per_level: 2,
            ..Selection::default()
        };

        let marks = selection.marks(&candidates());

        assert_eq!(selection.chosen(&candidates()), [1, 4, 5, 6]);
        assert_eq!(marks.get(6), Some(&Mark::Capped));
        assert_eq!(marks.get(7), Some(&Mark::Filtered));
    }

    #[test]
    fn hand_picked_jobs_win_over_the_filters_and_the_cap() {
        let mut selection = Selection {
            per_level: 1,
            ..Selection::default()
        };

        let all = candidates();
        selection.toggle(7, Mark::Capped);
        selection.toggle(8, Mark::Filtered);
        selection.toggle(5, Mark::Chosen);

        assert_eq!(selection.chosen(&all), [1, 4, 6, 7, 8]);

        selection.toggle(5, Mark::Excluded);
        selection.toggle(8, Mark::Included);
        selection.toggle(3, Mark::Refused("waits for review"));

        assert_eq!(selection.chosen(&all), [1, 4, 5, 7]);
        assert!(selection.include.contains(&7) && !selection.include.contains(&3));
    }

    #[test]
    fn filters_combine() {
        let mut selection = Selection {
            per_level: 0,
            min_score: 35,
            ..Selection::default()
        };

        Selection::flip(&mut selection.reviews, "false_positive");
        assert_eq!(selection.chosen(&candidates()), [1, 5, 6]);

        selection.name = "B_Med".to_owned();
        assert_eq!(selection.chosen(&candidates()), [6]);

        Selection::flip(&mut selection.coverage, "dynamic_linux");
        assert!(selection.chosen(&candidates()).is_empty());
    }

    #[test]
    fn a_saved_selection_reads_back_and_may_leave_out_fields() {
        let selection = Selection {
            include: [5].into(),
            ..Selection::default()
        };

        let json = serde_json::to_string(&selection).unwrap();
        assert_eq!(serde_json::from_str::<Selection>(&json).unwrap(), selection);

        let partial: Selection = serde_json::from_str(r#"{"per_level": 3}"#).unwrap();
        assert_eq!(partial.per_level, 3);
        assert_eq!(partial.levels, Selection::default().levels);
    }
}
