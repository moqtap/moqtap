//! The Prior Group ID Gap and Prior Object ID Gap conditions that show across
//! the Objects of one fetch stream, on drafts 11-23. Each draft's `FetchGaps`
//! refuses what one Object shows on its own and hands its gaps here.
//!
//! A fetch stream carries its Groups in the requested Group Order and, within
//! a Group, its Objects in Object ID order: draft-11 Section 8.13 and
//! draft-23 Section 3.2.1, "Within each group, objects are sent in Object ID
//! order; subgroup ID is not used for ordering." So the Group before this one,
//! and the Object before this one in its Group, are the only ones a gap below
//! this Object can cover, and the only ones whose gap can hold this Object.

use crate::error::CodecError;

/// Which Prior gap conditions a draft states without contradicting itself.
// A build without every draft leaves some variants unused.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GapRules {
    /// draft-11 Section 10.1, draft-12 Section 10.1 and draft-13 Section 10.1:
    /// an Object may carry Prior Group ID Gap more than once, there is no Prior
    /// Object ID Gap, and no condition about a gap covering an earlier Object.
    Draft11To13,
    /// draft-14 Section 11.1, draft-14 Section 11.3, draft-15 Section 11.1 and
    /// draft-15 Section 11.2: one instance of each gap per Object, "An endpoint
    /// receives an Object with a Prior Group ID Gap covering an Object it
    /// previously received", its Prior Object ID Gap twin, and "An endpoint
    /// receives an Object with a Group ID within a previously communicated
    /// gap" and its twin.
    Draft14To15,
    /// Drafts 16-17 state the conditions of drafts 14-15, but
    /// draft-16 Section 2.1 and draft-17 Section 2.1 say of an Object known to
    /// exist: "From this state, it can transition to not existing, but not vice
    /// versa." A gap covering an Object already received is that transition, so
    /// the two covering conditions are ambiguous and not checked.
    Draft16To17,
    /// Drafts 18-22 add, in draft-18 Section 2.1, draft-19 Section 2.1,
    /// draft-20 Section 2.1, draft-21 Section 2.1.1 and draft-22 Section 2.1.2:
    /// "an endpoint can receive an Object after it has already recorded that
    /// the Object does not exist [...] This is not a protocol error and the
    /// Track is not malformed." So the two within-gap conditions are ambiguous
    /// too, and neither pair is checked.
    Draft18To22,
    /// draft-23 Section 10.8 and draft-23 Section 10.9 state all four, and
    /// draft-23 Section 2.1.2 drops both sentences above.
    Draft23On,
}

impl GapRules {
    /// A gap covering the Group or Object before it on the stream is refused.
    fn checks_covering(self) -> bool {
        matches!(self, Self::Draft14To15 | Self::Draft23On)
    }

    /// A Group or Object within the gap the one before it communicated is
    /// refused.
    fn checks_within(self) -> bool {
        !matches!(self, Self::Draft18To22)
    }
}

/// The Prior gap state of one fetch stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FetchGapTracker {
    rules: GapRules,
    run: Option<GroupRun>,
    /// The Group before the current one, and the gap it communicated.
    earlier: Option<(u64, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupRun {
    group_id: u64,
    /// The values every Object of the Group that carried a gap carried, or
    /// `None` before the first such Object.
    common: Option<Vec<u64>>,
    /// The gap the Group communicated: whichever value is taken as each
    /// Object's, the gap is at least this. 0 while no Object carried one.
    communicated: u64,
    /// The latest Object of the Group, and its Prior Object ID Gap.
    last_object: Option<(u64, Option<u64>)>,
}

impl FetchGapTracker {
    pub(crate) fn new(rules: GapRules) -> Self {
        Self { rules, run: None, earlier: None }
    }

    /// Check the next Object, whose gaps its draft's `PriorGaps` has already
    /// held to its Group ID and Object ID. Records the Object only when it
    /// passes.
    pub(crate) fn check(
        &mut self,
        group_id: u64,
        object_id: u64,
        group_gaps: &[u64],
        object_gap: Option<u64>,
    ) -> Result<(), CodecError> {
        let mut earlier = self.earlier;
        let mut run = match &self.run {
            Some(run) if run.group_id == group_id => run.clone(),
            other => {
                if let Some(prior) = other {
                    earlier = Some((prior.group_id, prior.communicated));
                }
                GroupRun { group_id, common: None, communicated: 0, last_object: None }
            }
        };

        if let Some((prior, gap)) = earlier {
            if self.rules.checks_within() && group_id < prior && group_id >= prior - gap {
                return Err(malformed(format!(
                    "Group {group_id} is within the Prior Group ID Gap {gap} that Group {prior} \
                     communicated"
                )));
            }
            if self.rules.checks_covering() {
                if let Some(&gap) =
                    group_gaps.iter().find(|&&gap| prior < group_id && prior >= group_id - gap)
                {
                    return Err(malformed(format!(
                        "Prior Group ID Gap {gap} of Group {group_id} covers Group {prior}, \
                         received earlier"
                    )));
                }
            }
        }

        if !group_gaps.is_empty() {
            let common: Vec<u64> = match &run.common {
                Some(common) => common.iter().copied().filter(|v| group_gaps.contains(v)).collect(),
                None => {
                    let mut values = group_gaps.to_vec();
                    values.sort_unstable();
                    values.dedup();
                    values
                }
            };
            if common.is_empty() {
                return Err(malformed(match self.rules {
                    GapRules::Draft11To13 => format!(
                        "the Objects in Group {group_id} carry no Prior Group ID Gap value in common"
                    ),
                    _ => format!(
                        "two Objects in Group {group_id} carry different Prior Group ID Gap values"
                    ),
                }));
            }
            run.common = Some(common);
            let least = group_gaps.iter().copied().min().unwrap_or(0);
            run.communicated = run.communicated.max(least);
        }

        if let Some((prior, prior_gap)) = run.last_object {
            if let Some(gap) = object_gap.filter(|_| self.rules.checks_covering()) {
                if gap > 0 && prior < object_id && prior >= object_id - gap {
                    return Err(malformed(format!(
                        "Prior Object ID Gap {gap} of Object {object_id} covers Object {prior}"
                    )));
                }
            }
            if let Some(gap) = prior_gap.filter(|_| self.rules.checks_within()) {
                if object_id < prior && object_id >= prior - gap {
                    return Err(malformed(format!(
                        "Object {object_id} is within the Prior Object ID Gap {gap} that Object \
                         {prior} communicated"
                    )));
                }
            }
        }
        run.last_object = Some((object_id, object_gap));

        self.earlier = earlier;
        self.run = Some(run);
        Ok(())
    }
}

fn malformed(detail: String) -> CodecError {
    CodecError::MalformedTrack { detail }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(r: Result<(), CodecError>) -> bool {
        matches!(r, Err(CodecError::MalformedTrack { .. }))
    }

    #[test]
    fn objects_of_one_group_with_different_values_are_refused() {
        let mut t = FetchGapTracker::new(GapRules::Draft23On);
        t.check(5, 0, &[2], None).unwrap();
        t.check(5, 1, &[], None).unwrap();
        assert!(refused(t.check(5, 2, &[3], None)));
    }

    #[test]
    fn groups_are_compared_separately() {
        let mut t = FetchGapTracker::new(GapRules::Draft23On);
        t.check(5, 0, &[1], None).unwrap();
        t.check(7, 0, &[1], None).unwrap();
    }

    #[test]
    fn a_failed_check_records_nothing() {
        let mut t = FetchGapTracker::new(GapRules::Draft23On);
        t.check(5, 0, &[2], None).unwrap();
        assert!(refused(t.check(5, 1, &[3], None)));
        t.check(5, 2, &[2], None).unwrap();
    }

    #[test]
    fn a_group_gap_covering_the_group_before_is_refused_from_draft_14() {
        let mut t = FetchGapTracker::new(GapRules::Draft23On);
        t.check(8, 0, &[], None).unwrap();
        assert!(refused(t.check(10, 0, &[2], None)));
        let mut t = FetchGapTracker::new(GapRules::Draft23On);
        t.check(7, 0, &[], None).unwrap();
        t.check(10, 0, &[2], None).unwrap();
        let mut t = FetchGapTracker::new(GapRules::Draft11To13);
        t.check(8, 0, &[], None).unwrap();
        t.check(10, 0, &[2], None).unwrap();
    }

    #[test]
    fn a_group_within_the_gap_the_group_before_communicated_is_refused() {
        for rules in [GapRules::Draft11To13, GapRules::Draft23On] {
            let mut t = FetchGapTracker::new(rules);
            t.check(10, 0, &[2], None).unwrap();
            assert!(refused(t.check(9, 0, &[], None)));
            let mut t = FetchGapTracker::new(rules);
            t.check(10, 0, &[2], None).unwrap();
            t.check(7, 0, &[], None).unwrap();
        }
    }

    #[test]
    fn the_least_of_one_objects_values_is_the_gap_it_communicated() {
        let mut t = FetchGapTracker::new(GapRules::Draft11To13);
        t.check(10, 0, &[1, 3], None).unwrap();
        t.check(8, 0, &[], None).unwrap();
        let mut t = FetchGapTracker::new(GapRules::Draft11To13);
        t.check(10, 0, &[1, 3], None).unwrap();
        assert!(refused(t.check(9, 0, &[], None)));
    }

    #[test]
    fn objects_of_one_group_with_a_value_in_common_are_accepted_on_drafts_11_to_13() {
        let mut t = FetchGapTracker::new(GapRules::Draft11To13);
        t.check(5, 0, &[2, 3], None).unwrap();
        t.check(5, 1, &[3, 4], None).unwrap();
        assert!(refused(t.check(5, 2, &[2], None)));
    }

    #[test]
    fn an_object_gap_covering_the_object_before_is_refused() {
        let mut t = FetchGapTracker::new(GapRules::Draft23On);
        t.check(3, 8, &[], None).unwrap();
        assert!(refused(t.check(3, 10, &[], Some(2))));
        let mut t = FetchGapTracker::new(GapRules::Draft23On);
        t.check(3, 7, &[], None).unwrap();
        t.check(3, 10, &[], Some(2)).unwrap();
        t.check(4, 2, &[], Some(2)).unwrap();
    }

    #[test]
    fn an_object_within_the_gap_the_object_before_communicated_is_refused() {
        let mut t = FetchGapTracker::new(GapRules::Draft23On);
        t.check(3, 10, &[], Some(2)).unwrap();
        assert!(refused(t.check(3, 9, &[], None)));
    }

    #[test]
    fn drafts_16_to_17_do_not_refuse_a_covering_gap() {
        let mut t = FetchGapTracker::new(GapRules::Draft16To17);
        t.check(9, 0, &[], None).unwrap();
        t.check(10, 0, &[1], None).unwrap();
        t.check(10, 1, &[1], Some(1)).unwrap();
        let mut t = FetchGapTracker::new(GapRules::Draft16To17);
        t.check(10, 0, &[2], None).unwrap();
        assert!(refused(t.check(9, 0, &[], None)));
    }

    #[test]
    fn drafts_18_to_22_refuse_neither_covering_nor_within() {
        let mut t = FetchGapTracker::new(GapRules::Draft18To22);
        t.check(9, 0, &[], None).unwrap();
        t.check(10, 0, &[1], None).unwrap();
        t.check(10, 3, &[1], Some(2)).unwrap();
        t.check(10, 2, &[1], None).unwrap();
        t.check(9, 1, &[1], None).unwrap();
        assert!(refused(t.check(9, 2, &[2], None)));
    }
}
