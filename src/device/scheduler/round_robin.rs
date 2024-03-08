use std::{collections::LinkedList, sync::Mutex};

use crate::device::ToCardWorkRbDesc;

use super::SchedulerStrategy;

/// The round-robin strategy for the scheduler.
pub struct RoundRobinStrategy {
    queue: Mutex<LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)>>,
}

impl RoundRobinStrategy {
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(LinkedList::new()),
        }
    }
}

impl Default for RoundRobinStrategy {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: SchedulerStrategy should guarantee that it is thread safe
unsafe impl Send for RoundRobinStrategy {}
unsafe impl Sync for RoundRobinStrategy {}

impl SchedulerStrategy for RoundRobinStrategy {
    fn push(&self, qpn: u32, desc: LinkedList<ToCardWorkRbDesc>) {
        for i in self.queue.lock().unwrap().iter_mut() {
            // merge the descriptor if the qpn is already in the queue
            if i.0 == qpn {
                i.1.extend(desc);
                return;
            }
        }

        self.queue.lock().unwrap().push_back((qpn, desc));
    }

    fn pop(&self) -> Option<ToCardWorkRbDesc> {
        let mut guard = self.queue.lock().unwrap();
        let desc = if let Some((_, list)) = guard.front_mut() {
            list.pop_front().unwrap()
        } else {
            return None;
        };
        let (qpn, list) = guard.pop_front().unwrap();
        if !list.is_empty() {
            guard.push_back((qpn, list));
        }
        Some(desc)
    }

    fn is_empty(&self) -> bool {
        self.queue.lock().unwrap().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use crate::scheduler::{round_robin::RoundRobinStrategy, bench::generate_random_descriptors, SchedulerStrategy, get_to_card_desc_common};

    #[test]
    fn test_round_robin() {
        let round_robin = RoundRobinStrategy::new();
        let qpn1 = 1;
        let qpn2 = 2;
        let qpn1_descs = generate_random_descriptors(1, 2);
        round_robin.push(qpn1, qpn1_descs);
        let qpn2_descs = generate_random_descriptors(2, 3);
        round_robin.push(qpn2, qpn2_descs);
        let result_dqpns = [1, 2, 1, 2, 2];
        for result_dqpn in result_dqpns {
            let desc = round_robin.pop().unwrap();
            let item = get_to_card_desc_common(&desc).dqpn;
            assert_eq!(item, result_dqpn);
        }
        assert!(round_robin.is_empty());

        // test merge descriptors
        let qpn1_descs = generate_random_descriptors(1, 2);
        round_robin.push(qpn1, qpn1_descs);
        let qpn2_descs = generate_random_descriptors(2, 3);
        round_robin.push(qpn2, qpn2_descs);
        let desc = round_robin.pop().unwrap();
        let item1 = get_to_card_desc_common(&desc).dqpn;
        assert_eq!(item1, 1);
        // should be {qpn1 : 3 items, qpn2 : 3 items}, next is qpn2
        let qpn1_descs = generate_random_descriptors(1, 2);
        round_robin.push(qpn1, qpn1_descs);
        let result_dqpns = [2, 1, 2, 1, 2, 1];
        for result_dqpn in result_dqpns {
            let desc = round_robin.pop().unwrap();
            let item = get_to_card_desc_common(&desc).dqpn;
            assert_eq!(item, result_dqpn);
        }
        assert!(round_robin.is_empty());
    }
}
