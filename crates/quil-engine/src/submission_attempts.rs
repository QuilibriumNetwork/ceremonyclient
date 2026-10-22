//! Shared ownership of asynchronous shard operations. Reservations survive
//! preparation and block other operation kinds until completion; successful
//! publication retains a bounded retry fence, not a registry acknowledgement.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const RETRY_FRAMES: u64 = 30;
type Key = (u64, Vec<u8>);

#[derive(Default)]
pub(crate) struct SubmissionAttempts(Mutex<HashMap<Key, Attempt>>);

struct Attempt {
    frame: u64,
    in_flight: bool,
    /// Fenced until its epoch ends rather than for the retry fence.
    for_epoch: bool,
}

impl Attempt {
    /// Whether this attempt of `attempt_epoch` still owns its filter at
    /// `frame` of `epoch`: in flight, or inside its fence.
    fn owns(&self, attempt_epoch: u64, epoch: u64, frame: u64) -> bool {
        self.in_flight
            || (attempt_epoch == epoch
                && (self.for_epoch || frame.saturating_sub(self.frame) < RETRY_FRAMES))
    }
}

pub(crate) struct SubmissionAttempt {
    owner: Arc<SubmissionAttempts>,
    keys: Vec<Key>,
    published_frames: HashMap<Vec<u8>, u64>,
    /// Filters fenced until the epoch ends (`fence_for_epoch`).
    epoch_fenced: Vec<Vec<u8>>,
}

impl SubmissionAttempts {
    /// Whether a local operation still owns `filter` at `frame`: one in
    /// flight, or a publication of this epoch inside its retry fence.
    pub(crate) fn owned(&self, filter: &[u8], frame: u64) -> bool {
        let epoch = quil_types::consensus::epoch_for_frame(frame);
        self.0.lock().is_ok_and(|attempts| attempts.iter().any(|((e, owned), a)| {
            owned.as_slice() == filter && a.owns(*e, epoch, frame)
        }))
    }

    pub(crate) fn begin(
        self: &Arc<Self>,
        filters: &[Vec<u8>],
        frame: u64,
    ) -> Option<SubmissionAttempt> {
        if filters.is_empty() {
            return None;
        }
        let epoch = quil_types::consensus::epoch_for_frame(frame);
        let mut attempts = self.0.lock().ok()?;
        attempts.retain(|(e, _), a| a.owns(*e, epoch, frame));
        if filters.iter().any(|f| {
            attempts
                .iter()
                .any(|((e, existing), a)| existing == f && (a.in_flight || *e == epoch))
        }) {
            return None;
        }
        let keys: Vec<Key> = filters.iter().map(|f| (epoch, f.clone())).collect();
        for key in &keys {
            attempts.insert(
                key.clone(),
                Attempt {
                    frame,
                    in_flight: true,
                    for_epoch: false,
                },
            );
        }
        Some(SubmissionAttempt {
            owner: self.clone(),
            keys,
            published_frames: HashMap::new(),
            epoch_fenced: Vec::new(),
        })
    }
}

impl SubmissionAttempt {
    /// Every filter published at `frame`; senders record each message's
    /// filters with `published_subset` as it goes out.
    #[cfg(test)]
    pub(crate) fn published(mut self, frame: u64) {
        for (_, filter) in &self.keys {
            self.published_frames.insert(filter.clone(), frame);
        }
    }

    /// Release `filters` before the rest of the attempt finishes: the attempt
    /// left them out and neither prepares nor submits them any more, so the
    /// next cycle may retry them while the others are still published.
    pub(crate) fn release(&mut self, filters: &[Vec<u8>]) {
        let (released, kept): (Vec<Key>, Vec<Key>) = std::mem::take(&mut self.keys)
            .into_iter()
            .partition(|(_, owned)| filters.contains(owned));
        self.keys = kept;
        if let Ok(mut attempts) = self.owner.0.lock() {
            for key in &released {
                attempts.remove(key);
            }
        }
    }

    /// A later chunk failure cannot erase ownership of an already published
    /// subset. Unpublished filters are released when this guard is dropped.
    pub(crate) fn published_subset(&mut self, filters: &[Vec<u8>], frame: u64) {
        self.fence(filters, frame);
    }

    /// Keep `filters` owned for the retry fence from `frame`, as if
    /// published: the attempt refused them for a reason retrying them on the
    /// next cycle would not change (an op no node decodes).
    pub(crate) fn fence(&mut self, filters: &[Vec<u8>], frame: u64) {
        for filter in filters {
            if self.keys.iter().any(|(_, owned)| owned == filter) {
                self.published_frames.insert(filter.clone(), frame);
            }
        }
    }

    /// Keep `filters` owned until the attempt's epoch ends: the attempt left
    /// them out for a reason that holds for the whole epoch (a seat over the
    /// decode limits), so preparing them again within it would only leave
    /// them out again. The next epoch's attempt retries them.
    pub(crate) fn fence_for_epoch(&mut self, filters: &[Vec<u8>], frame: u64) {
        self.fence(filters, frame);
        for filter in filters {
            if self.published_frames.contains_key(filter) {
                self.epoch_fenced.push(filter.clone());
            }
        }
    }
}

impl Drop for SubmissionAttempt {
    fn drop(&mut self) {
        if let Ok(mut attempts) = self.owner.0.lock() {
            for key in &self.keys {
                if let Some(&frame) = self.published_frames.get(&key.1) {
                    if let Some(a) = attempts.get_mut(key) {
                        a.in_flight = false;
                        a.frame = a.frame.max(frame);
                        a.for_epoch |= self.epoch_fenced.contains(&key.1);
                    }
                } else {
                    attempts.remove(key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_flight_failure_success_and_epoch_retry() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let filters = vec![vec![1]];
        let first = attempts.begin(&filters, 10).unwrap();
        assert!(attempts.begin(&filters, 100).is_none());
        drop(first); // Cancellation/failure releases the reservation.
        attempts.begin(&filters, 100).unwrap().published(100);
        assert!(attempts.begin(&filters, 101).is_none());
        assert!(attempts.begin(&filters, 130).is_some());
        attempts.begin(&filters, 719).unwrap().published(719);
        assert!(attempts.begin(&filters, 720).is_some());
    }

    #[test]
    fn cooldown_starts_when_preparation_and_publication_finish() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let filters = vec![vec![1]];
        attempts.begin(&filters, 10).unwrap().published(50);
        assert!(attempts.begin(&filters, 79).is_none());
        assert!(attempts.begin(&filters, 80).is_some());
    }

    #[test]
    fn later_chunk_failure_keeps_published_subset_reserved() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let mut guard = attempts.begin(&[vec![1], vec![2]], 10).unwrap();
        guard.published_subset(&[vec![1]], 12);
        drop(guard); // The other chunk failed before publication.
        assert!(attempts.begin(&[vec![1]], 13).is_none());
        assert!(attempts.begin(&[vec![2]], 13).is_some());
        assert!(attempts.begin(&[vec![1]], 42).is_some());
    }

    #[test]
    fn a_released_filter_is_free_while_the_rest_stays_reserved() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let mut guard = attempts.begin(&[vec![1], vec![2]], 10).unwrap();
        guard.release(&[vec![2]]);
        assert!(attempts.begin(&[vec![2]], 11).is_some(), "released at once");
        assert!(attempts.begin(&[vec![1]], 11).is_none(), "still in flight");
        guard.published(12);
        assert!(attempts.begin(&[vec![1]], 13).is_none(), "published: fenced");
        assert!(attempts.begin(&[vec![2]], 13).is_some(), "released: not fenced");
    }

    #[test]
    fn an_epoch_fence_lasts_until_the_epoch_ends() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let mut guard = attempts.begin(&[vec![1], vec![2]], 10).unwrap();
        guard.fence_for_epoch(&[vec![1]], 12);
        guard.fence(&[vec![2]], 12);
        drop(guard);
        assert!(attempts.begin(&[vec![2]], 42).is_some(), "the retry fence lapses");
        assert!(attempts.owned(&[1], 719), "the epoch fence holds to the epoch's last frame");
        assert!(attempts.begin(&[vec![1]], 719).is_none());
        assert!(!attempts.owned(&[1], 720), "and lapses with it");
        assert!(attempts.begin(&[vec![1]], 720).is_some(), "the next epoch retries it");
    }

    #[test]
    fn running_task_retains_ownership_across_epoch_boundaries() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let running = attempts.begin(&[vec![1]], 719).unwrap();
        assert!(attempts.begin(&[vec![1]], 720).is_none());
        assert!(attempts.begin(&[vec![1]], 1440).is_none());
        drop(running);
        assert!(attempts.begin(&[vec![1]], 1440).is_some());
    }

    #[test]
    fn ownership_covers_running_and_fenced_attempts() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let running = attempts.begin(&[vec![1]], 10).unwrap();
        assert!(attempts.owned(&[1], 2000), "a running attempt owns its filter across epochs");
        assert!(!attempts.owned(&[2], 10));
        running.published(20);
        assert!(attempts.owned(&[1], 49));
        assert!(!attempts.owned(&[1], 50), "the fence ends ownership");
    }

    #[test]
    fn overlapping_batches_cannot_encode_the_same_filter_concurrently() {
        let attempts = Arc::new(SubmissionAttempts::default());
        let guard = attempts.begin(&[vec![1], vec![2]], 10).unwrap();
        assert!(attempts.begin(&[vec![2], vec![3]], 11).is_none());
        assert!(attempts.begin(&[vec![3]], 11).is_some());
        drop(guard);
        assert!(attempts.begin(&[vec![2]], 12).is_some());
    }
}
