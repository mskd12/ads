mod test;

use fastcrypto::hash::{Blake2b256, HashFunction};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq)]
pub enum NodeType {
    Internal,
    Leaf,
}

// A struct representing a Merkle Tree Node
#[derive(Debug, Clone)]
pub struct MerkleNode {
    pub hash: Vec<u8>,
    pub node_type: NodeType,
    pub value: Option<Vec<u8>>, // None for internal nodes, Some for leaf nodes
    pub left: Option<Box<MerkleNode>>, // None for leaf nodes, Some for internal nodes
    pub right: Option<Box<MerkleNode>>, // Same as above
    pub height: usize,
}

#[derive(Serialize)]
struct HashPair {
    left: Vec<u8>,
    right: Vec<u8>,
}

impl MerkleNode {
    fn new_leaf(value: Vec<u8>) -> Self {
        // assert!(value.len() == 32);
        MerkleNode {
            hash: value.clone(),
            node_type: NodeType::Leaf,
            value: Some(value),
            left: None,
            right: None,
            height: 0,
        }
    }

    fn from_children(left: MerkleNode, right: MerkleNode) -> Self {
        assert!(left.height == right.height);
        let height = left.height + 1;
        let bytes = bcs::to_bytes(&HashPair {
            left: left.hash.clone(),
            right: right.hash.clone(),
        })
        .unwrap();
        let hash = Blake2b256::digest(&bytes).to_vec();

        MerkleNode {
            hash,
            node_type: NodeType::Internal,
            value: None,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
            height,
        }
    }
}

/// A struct representing a Perfect Binary Merkle Tree, i.e., one storing 2^n leaves.
/// This is storing the entire tree in heap memory for the PoC. We'd want to optimize this in practice.
#[derive(Debug)]
pub struct PerfectMerkleTree {
    pub root: MerkleNode,
}

impl PerfectMerkleTree {
    pub fn new(data_blocks: Vec<&[u8]>) -> Self {
        let mut nodes = data_blocks
            .iter()
            .map(|&data| MerkleNode::new_leaf(data.to_vec()))
            .collect::<Vec<_>>();

        while nodes.len() > 1 {
            if nodes.len() % 2 != 0 {
                // Throw an error
                panic!(
                    "Not a perfect binary tree! Odd number of nodes at some level ({})",
                    nodes.len()
                );
            }

            // Note: Do we actually need to clone the nodes?
            nodes = nodes
                .chunks(2)
                .map(|chunk| MerkleNode::from_children(chunk[0].clone(), chunk[1].clone()))
                .collect();
        }

        PerfectMerkleTree {
            root: nodes.into_iter().next().unwrap(),
        }
    }

    fn height(&self) -> usize {
        self.root.height
    }

    pub fn num_leaves(&self) -> usize {
        2usize.pow(self.height() as u32)
    }

    pub fn pretty_print(&self) {
        let mut stack = vec![(0, &self.root, "root".to_string())];
        while let Some((indent, node, label)) = stack.pop() {
            // println!("{}{}{}", " ".repeat(indent), hex_string(&node.hash), node.value.as_ref().map_or("".to_string(), |v| format!(" ({})", String::from_utf8_lossy(v))));
            // Include the label, hash and value in the output
            println!(
                "{}[{}] {}{}",
                " ".repeat(indent),
                label,
                hex_string(&node.hash),
                node.value.as_ref().map_or("".to_string(), |v| format!(
                    " ({})",
                    String::from_utf8_lossy(v)
                ))
            );
            if let Some(right) = &node.right {
                stack.push((indent + 2, right, "right".to_string()));
            }
            if let Some(left) = &node.left {
                stack.push((indent + 2, left, "left".to_string()));
            }
        }
    }

    fn digest(&self) -> &[u8] {
        &self.root.hash
    }
}

// A struct representing a proof of the most recent n elements in a Perfect Merkle Tree.
#[derive(Debug, Clone)]
pub struct SuffixProof {
    pub num_suffix_elements: usize,
    pub proof: Vec<Vec<u8>>,
}

impl PerfectMerkleTree {
    pub fn prove_most_recent_n_elements(&self, num_suffix_elements: usize) -> SuffixProof {
        assert!(num_suffix_elements > 0);
        assert!(num_suffix_elements <= self.num_leaves());

        let mut proof_nodes = Vec::new();
        let num_leaves = self.num_leaves();
        let first_suffix_index = num_leaves - num_suffix_elements;

        // Recursively collect proof nodes
        self.collect_proof_nodes(
            &self.root,
            0,
            num_leaves,
            first_suffix_index,
            num_suffix_elements,
            &mut proof_nodes,
        );

        SuffixProof {
            num_suffix_elements,
            proof: proof_nodes,
        }
    }

    fn collect_proof_nodes(
        &self,
        node: &MerkleNode,
        subtree_start: usize,
        subtree_size: usize,
        first_suffix_index: usize,
        suffix_size: usize,
        proof_nodes: &mut Vec<Vec<u8>>,
    ) {
        if subtree_size == 1 {
            // This is a leaf
            return;
        }

        let mid = subtree_start + subtree_size / 2;

        // With current construction, the "later" elements are in the right subtree
        if first_suffix_index >= mid {
            // Suffix is entirely in right subtree (which contains later elements)
            // Add left subtree to proof
            if let Some(left) = &node.left {
                proof_nodes.push(left.hash.clone());
            }
            if let Some(right) = &node.right {
                self.collect_proof_nodes(
                    right,
                    mid,
                    subtree_size / 2,
                    first_suffix_index,
                    suffix_size,
                    proof_nodes,
                );
            }
        } else if first_suffix_index + suffix_size <= mid {
            // Suffix is entirely in left subtree (which contains earlier elements)
            // Add right subtree to proof
            if let Some(right) = &node.right {
                proof_nodes.push(right.hash.clone());
            }
            if let Some(left) = &node.left {
                self.collect_proof_nodes(
                    left,
                    subtree_start,
                    subtree_size / 2,
                    first_suffix_index,
                    suffix_size,
                    proof_nodes,
                );
            }
        } else {
            // Suffix spans both subtrees
            if let Some(left) = &node.left {
                self.collect_proof_nodes(
                    left,
                    subtree_start,
                    subtree_size / 2,
                    first_suffix_index,
                    mid - first_suffix_index,
                    proof_nodes,
                );
            }
            if let Some(right) = &node.right {
                self.collect_proof_nodes(
                    right,
                    mid,
                    subtree_size / 2,
                    mid,
                    first_suffix_index + suffix_size - mid,
                    proof_nodes,
                );
            }
        }
    }

    pub fn verify_suffix_proof(&self, suffix_elements: &[Vec<u8>], proof: &SuffixProof) {
        assert_eq!(suffix_elements.len(), proof.num_suffix_elements);

        let num_leaves = self.num_leaves();
        let first_suffix_index = num_leaves - proof.num_suffix_elements;

        // Build up the tree from suffix elements
        let mut current_hashes = suffix_elements.to_vec();
        let mut proof_index = proof.proof.len();
        let mut level_start_index = first_suffix_index;
        let mut level_size = proof.num_suffix_elements;

        // Build tree level by level
        while current_hashes.len() > 1 || level_start_index > 0 {
            let mut next_level = Vec::new();
            let mut i = 0;

            // Check if we need a left sibling from proof
            if level_start_index % 2 == 1 {
                // Need left sibling from proof
                assert!(proof_index > 0, "Not enough proof elements");
                proof_index -= 1;
                let left_sibling = &proof.proof[proof_index];
                let right = &current_hashes[0];

                // Hash them together - match tree construction order
                let bytes = bcs::to_bytes(&HashPair {
                    left: left_sibling.clone(), // Left sibling
                    right: right.clone(),       // Right child (our suffix)
                })
                .unwrap();
                next_level.push(Blake2b256::digest(&bytes).to_vec());

                i = 1;
                level_start_index -= 1;
            }

            // Pair up remaining elements (note: tree uses reversed order)
            while i < current_hashes.len() {
                if i + 1 < current_hashes.len() {
                    // Pair two elements - match tree construction order
                    let bytes = bcs::to_bytes(&HashPair {
                        left: current_hashes[i].clone(),      // Left child
                        right: current_hashes[i + 1].clone(), // Right child
                    })
                    .unwrap();
                    next_level.push(Blake2b256::digest(&bytes).to_vec());
                    i += 2;
                } else {
                    // Odd element, carry forward
                    next_level.push(current_hashes[i].clone());
                    i += 1;
                }
            }

            current_hashes = next_level;
            level_start_index /= 2;
            level_size = (level_size + 1) / 2;
        }

        assert_eq!(proof_index, 0, "Not all proof elements were used");
        assert_eq!(current_hashes.len(), 1, "Should have exactly one root hash");

        // Check that the computed root matches the actual root
        assert_eq!(
            current_hashes[0], self.root.hash,
            "Computed root doesn't match expected root"
        );
    }
}

/**
 * A struct representing a Merkle Forest, i.e., a collection of Perfect Merkle Trees.
 * Extends PerfectMerkleTree to support #leaves that are not a power of 2.
 *
 * For example, if the total number of leaves is 133 or 10000101 in binary,
 * then we will have three PerfectMerkleTrees of leaves 2^0, 2^2 and 2^7 respectively.
 * In particular, trees[0] has 1 leaf, trees[2] has 4 leaves and trees[7] has 128 leaves.
 */
#[derive(Debug)]
pub struct MerkleMountainRange {
    pub entries: Vec<Vec<u8>>,
    pub trees: Vec<Option<PerfectMerkleTree>>,
}

impl MerkleMountainRange {
    pub fn new(entries: Vec<&[u8]>) -> Self {
        let mut mmr = MerkleMountainRange {
            entries: vec![],
            trees: vec![None],
        };

        for entry in entries {
            mmr.add_entry(entry);
        }

        mmr
    }

    pub fn add_entry(&mut self, entry: &[u8]) {
        self.entries.push(entry.to_vec());

        let mut i = MerkleNode::new_leaf(entry.to_vec());
        for tree in self.trees.iter_mut() {
            if let Some(t) = tree.take() {
                i = MerkleNode::from_children(t.root, i);
            } else {
                // Make i the root of current tree
                *tree = Some(PerfectMerkleTree { root: i });
                break;
            };
        }

        if self.trees.last().unwrap().is_some() {
            self.trees.push(None);
        }
    }

    pub fn pretty_print(&self) {
        println!(
            "Entries: {:?}",
            self.entries
                .iter()
                .map(|e| hex_string(e))
                .collect::<Vec<_>>()
        );
        for (i, tree) in self.trees.iter().enumerate() {
            println!("Tree {}", i);
            if let Some(tree) = tree {
                tree.pretty_print();
            } else {
                println!("Empty");
            }
        }
    }

    fn digests(&self) -> Vec<Vec<u8>> {
        let mut digests = vec![];
        for tree in &self.trees {
            if let Some(tree) = tree {
                digests.push(tree.digest().to_vec());
            } else {
                digests.push(vec![]);
            }
        }
        digests
    }
}

/// The most recent n elements proof contains some full trees and at most one partial tree.
pub struct MostRecentNElementsProof {
    pub entries: Vec<Vec<u8>>,
    // Indices of trees that contain all the elements in the proof
    pub full_tree_indices: Vec<usize>,
    // If N is an exact span of some trees, then this is None.
    pub partial_tree_proof: Option<(usize, SuffixProof)>,
}

impl MerkleMountainRange {
    pub fn prove_most_recent_n_elements(
        &self,
        num_suffix_elements: usize,
    ) -> MostRecentNElementsProof {
        assert!(num_suffix_elements <= self.entries.len());

        // Take the LAST num_suffix_elements from entries (most recent)
        let start_index = self.entries.len() - num_suffix_elements;
        let suffix_entries = self.entries[start_index..].to_vec();

        let mut remaining_elements = num_suffix_elements;
        let mut proof = MostRecentNElementsProof {
            entries: suffix_entries,
            full_tree_indices: vec![],
            partial_tree_proof: None,
        };

        // Iterate trees from smallest to largest (they contain most recent to oldest)
        for (tree_index, tree) in self.trees.iter().enumerate() {
            if remaining_elements == 0 {
                break;
            }
            if let Some(tree) = tree {
                if tree.num_leaves() <= remaining_elements {
                    remaining_elements -= tree.num_leaves();
                    proof.full_tree_indices.push(tree_index);
                } else {
                    // Need partial proof from this tree
                    proof.partial_tree_proof = Some((
                        tree_index,
                        tree.prove_most_recent_n_elements(remaining_elements),
                    ));
                    return proof;
                }
            }
        }
        assert!(remaining_elements == 0);
        proof
    }

    pub fn verify_most_recent_n_elements(&self, proof: &MostRecentNElementsProof) {
        // Check that provided entries are non-empty
        assert!(!proof.entries.is_empty(), "Proof entries cannot be empty");

        let num_suffix_elements = proof.entries.len();
        let mut total_leaves_covered = 0;

        // First, handle partial tree if present (it contains the oldest elements)
        let mut entry_offset = 0;
        if let Some((tree_index, ref suffix_proof)) = proof.partial_tree_proof {
            assert!(
                tree_index < self.trees.len(),
                "Tree index {} out of bounds",
                tree_index
            );

            let Some(tree) = &self.trees[tree_index] else {
                panic!("Tree at index {} doesn't exist", tree_index);
            };

            let partial_elements = suffix_proof.num_suffix_elements;
            total_leaves_covered += partial_elements;

            // Partial tree gets the first (oldest) elements
            assert!(
                partial_elements <= proof.entries.len(),
                "Partial tree entries out of bounds"
            );
            let tree_entries = &proof.entries[0..partial_elements];

            tree.verify_suffix_proof(tree_entries, suffix_proof);

            entry_offset = partial_elements;
        }

        // Then process full trees from largest index to smallest
        // (from oldest to most recent in terms of data)
        for &tree_index in proof.full_tree_indices.iter().rev() {
            assert!(
                tree_index < self.trees.len(),
                "Tree index {} out of bounds",
                tree_index
            );

            let Some(tree) = &self.trees[tree_index] else {
                panic!("Tree at index {} doesn't exist", tree_index);
            };

            let tree_leaves = tree.num_leaves();
            total_leaves_covered += tree_leaves;

            // Get the entries for this tree
            let tree_entries_end = entry_offset + tree_leaves;
            assert!(
                tree_entries_end <= proof.entries.len(),
                "Tree entries out of bounds"
            );
            let tree_entries = &proof.entries[entry_offset..tree_entries_end];
            entry_offset = tree_entries_end;

            // Reconstruct and verify root for full tree
            let tree_entries_refs: Vec<&[u8]> = tree_entries.iter().map(|e| e.as_slice()).collect();

            let reconstructed = PerfectMerkleTree::new(tree_entries_refs);
            assert_eq!(
                reconstructed.digest(),
                tree.digest(),
                "Reconstructed tree digest doesn't match expected"
            );
        }

        // Check that all entries were accounted for
        assert_eq!(
            total_leaves_covered, num_suffix_elements,
            "Not all entries were accounted for"
        );
    }
}

////// Helper functions

// Print hash in hex format
fn hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
}

// ceil(log_2) + 1
fn num_trees(n: usize) -> usize {
    let x = (n as f64).log2().ceil() as usize;

    // if n is a power of 2, then return x + 1 else return x
    if n == 2usize.pow(x as u32) {
        x + 2
    } else {
        x + 1
    }
}
