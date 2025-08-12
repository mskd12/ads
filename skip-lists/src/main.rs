use std::{collections::HashMap, fmt::Display};
use sha2::{Digest as Sha2Digest, Sha256};
use serde::Serialize;
use bcs::to_bytes;

const DEFAULT_BASE: u64 = 10;

#[derive(Copy, Clone, Debug)]
pub struct Digest {
    pub bytes: [u8; 32]
}

/// A node in a skip list
#[derive(Debug, Clone)]
pub struct Node<T> {
    /// Value
    pub value: T,
    /// Height of current node
    pub height: u64,
    /// A list of previous nodes & their heights. Useful for short inclusion proofs.
    /// We store at most log_b(h) fingers
    pub fingers: HashMap<u64, Digest>
}

pub struct SkipList<T> {
    pub nodes: Vec<Node<T> >,
}

impl<T> Node<T> where T: Copy + Serialize {
    /// The first node in a skip list
    pub fn first(val: T) -> Node<T> {
        Node {
            value: val,
            height: 1,
            fingers: HashMap::<u64, Digest>::new()
        }
    }

    pub fn digest(&self) -> Digest {
        // Compute sha256 hash of the value, height and fingers
        let mut hasher = Sha256::new();
        hasher.update(&to_bytes(&self.value).unwrap());
        hasher.update(&self.height.to_le_bytes());
        // Iterate over fingers in increasing order of indices
        let mut finger_indices: Vec<u64> = self.fingers.keys().cloned().collect();
        finger_indices.sort();
        for idx in finger_indices {
            let digest = self.fingers.get(&idx).expect("Finger not found");
            hasher.update(&idx.to_le_bytes());
            hasher.update(&digest.bytes);
        }
        let result = hasher.finalize();
        Digest {
            bytes: result.into()
        }
    }

    /// Calculate the next node given the latest node & new value
    pub fn next(&self, new_value: T) -> Node<T> {
        Node {
            value: new_value,
            height: self.height + 1,
            fingers: self.next_fingers()
        }
    }

    /// Calculates the next fingers using the current ones
    fn next_fingers(&self) -> HashMap<u64, Digest> {
        let next_height = self.height + 1;
        let finger_indices = calculate_finger_indices(next_height, DEFAULT_BASE);
        let mut new_h = HashMap::new();
        let old_h = &self.fingers;
        for idx in finger_indices {
            match old_h.get(&idx) {
                Some(val) => {
                    new_h.insert(idx, *val);
                },
                None => {
                    if idx == self.height {
                        new_h.insert(idx, self.digest());
                    } else {
                        panic!("Unexpected idx {}", idx)
                    }
                }
            }
        }
        return new_h;
    }
}

/// Returns indices of fingers for the given height.
/// Fingers are nothing but greatest indices at different heights.
/// 
/// Algo: For a skip list of height h, the finger indices are calculated as follows:
/// For each base y in [1, base, base^2, ...], calculate z = ((h - 1) / y) * y.
/// The works because (h - 1) is guaranteed to be the greatest index at some height. 
/// And other greatest indices can be derived by replacing the last digit(s) in (height - 1) with zeroes.
pub fn calculate_finger_indices(height: u64, base: u64) -> Vec<u64> {
    let mut fingers = Vec::new();
    let x = height - 1;
    let mut y = 1;
    while x >= y {
        let z = (x / y) * y;
        if !fingers.contains(&z) { // To omit duplicates
            fingers.push(z);
        }
        y = y * base;
    }
    fingers
}

impl<T: Copy + Serialize + Display> SkipList<T> {
    pub fn new() -> SkipList<T> {
        return SkipList {
            nodes: Vec::new(),
        }
    }

    // Add a new value to the skip list.
    pub fn add(&mut self, value: T) {
        let new_node = match self.nodes.last() {
            Some(node) => {
                node.next(value)
            },
            None => { // nodes.len() == 0
                Node::<T>::first(value)
            }
        };
        self.nodes.push(new_node);
    }

    /// Get an inclusion proof for the node at height h w.r.t the latest head
    pub fn get_inclusion_proof(&self, h: u64) -> Vec<Node<T> > {
        assert!(h <= self.nodes.len() as u64);

        let mut path = Vec::new();
        let mut cur_node = self.nodes.last().expect("One node must exist");
        while cur_node.height > h {
            path.push(cur_node.clone());

            let closest_finger = cur_node
                .fingers
                .keys()
                .filter(|&&finger| finger >= h)
                .min_by_key(|&&finger| finger - h)
                .expect("At least one finger must be found");

            cur_node = &self.nodes[*closest_finger as usize - 1]; // -1 because height is 1-indexed
        }
        
        if cur_node.height < h {
            panic!("Should not happen")
        }

        path
    }

    /// Print finger indices w/o the digests
    pub fn short_print(&self) {
        for (i, node) in self.nodes.iter().enumerate() {
            println!("Node {}: Value: {}, Height: {}", i, node.value, node.height);
            if node.fingers.is_empty() {
                println!("  Fingers: None");
            } else {
                let mut finger_indices: Vec<u64> = node.fingers.keys().cloned().collect();
                finger_indices.sort();
                println!("  Fingers: {:?}", finger_indices);
            }
        }
    }
}

mod test {
    use super::*;

    #[test]
    pub fn test_calculate_finger_indices() {
        assert_eq!(calculate_finger_indices(2, 10), vec![1]);

        assert_eq!(calculate_finger_indices(10001, 10), vec![10000]);
        assert_eq!(calculate_finger_indices(10000, 10), vec![9999, 9990, 9900, 9000]);

        assert_eq!(calculate_finger_indices(5346, 10), vec![5345, 5340, 5300, 5000]);
        assert_eq!(calculate_finger_indices(5340, 10), vec![5339, 5330, 5300, 5000]);
        assert_eq!(calculate_finger_indices(5300, 10), vec![5299, 5290, 5200, 5000]);
        assert_eq!(calculate_finger_indices(5000, 10), vec![4999, 4990, 4900, 4000]);

        assert_eq!(calculate_finger_indices(5341, 10), vec![5340, 5300, 5000]);
        assert_eq!(calculate_finger_indices(15, 2), vec![14, 12, 8]);
    }

    // pub fn kostas_pruning() {
    //     assert_eq!(calculate_finger_indices(5346, 10), vec![5345, 5340]);
    //     assert_eq!(calculate_finger_indices(5340, 10), vec![5339, 5330, 5300]);
    //     assert_eq!(calculate_finger_indices(5300, 10), vec![5299, 5290, 5200, 5000]);
    //     assert_eq!(calculate_finger_indices(5000, 10), vec![4999, 4990, 4900, 4000]);
    // }

    #[test]
    pub fn test_skip_list_add() {
        let mut skip_list = SkipList::<u64>::new();
        let num_elements = 250;
        for i in 0..num_elements {
            skip_list.add(i);
        }
        // println!("Skip List: {:?}", skip_list.nodes);
        skip_list.short_print();

        assert_eq!(skip_list.nodes.len(), num_elements as usize);
        // Check the values
        for i in 0..num_elements {
            assert_eq!(skip_list.nodes[i as usize].value, i);
            assert_eq!(skip_list.nodes[i as usize].height, (i + 1) as u64);
        }

        // Elements with zero fingers
        let first_fingers = &skip_list.nodes[0].fingers;
        assert!(first_fingers.is_empty(), "First node should have no fingers");


        // Elements with one finger
        let mut prev_digest = skip_list.nodes[0].digest().bytes;
        for i in 1..11 {
            let node = &skip_list.nodes[i as usize];
            let fingers = &node.fingers;
            assert_eq!(fingers.len(), 1, "Node at index {} should have one finger", i);
            assert!(fingers.contains_key(&(i as u64)), "Node at index {} should have a finger at index {}", i, i);
            assert_eq!(fingers.get(&(i as u64)).unwrap().bytes, prev_digest, "Finger at index {} should point to previous node's digest", i);
            prev_digest = node.digest().bytes; // Update the digest for the next iteration
        }

        // Check the fingers of node at index 12
        let node_12 = &skip_list.nodes[12];
        let fingers_12 = &node_12.fingers;
        assert_eq!(fingers_12.len(), 2, "Node at index 12 should have two fingers");
        assert!(fingers_12.contains_key(&12), "Node at index 12 should have a finger at index 11");
        assert!(fingers_12.contains_key(&10), "Node at index 12 should have a finger at index 10");

        // Check the fingers of node at index 200
        let node_200 = &skip_list.nodes[200];
        let fingers_200 = &node_200.fingers;
        assert_eq!(fingers_200.len(), 1, "Node at index 200 should have one finger");
        assert!(fingers_200.contains_key(&200), "Node at index 200 should have a finger at index 200");
    }

    #[test]
    pub fn test_skip_list_inclusion() {
        let mut skip_list = SkipList::<u64>::new();
        for i in 1..1000 {
            skip_list.add(i);
        }

        let proof = skip_list.get_inclusion_proof(345);
        for node in &proof {
            println!("Node Height: {}, Value: {}", node.height, node.value);
        }
    }
}

fn main() {
    // Example usage of the skip list
    let mut skip_list = SkipList::<u64>::new();
    for i in 0..20 {
        skip_list.add(i);
    }
    skip_list.short_print();
}