mod test;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
enum NodeType {
    Internal,
    Leaf,
}

// A struct representing a Merkle Tree Node
#[derive(Debug, Clone)]
struct MerkleNode {
    hash: Vec<u8>,
    nodetype: NodeType,
    value: Option<Vec<u8>>, // None for internal nodes, Some for leaf nodes
    left: Option<Box<MerkleNode>>, // None for leaf nodes, Some for internal nodes
    right: Option<Box<MerkleNode>>, // Same as above 
}

impl MerkleNode {
    fn new_leaf(value: Vec<u8>) -> Self {
        let hash = Sha256::digest(&value).to_vec();
        MerkleNode {
            hash,
            nodetype: NodeType::Leaf,
            value: Some(value),
            left: None,
            right: None,
        }
    }

    fn from_children(left: MerkleNode, right: MerkleNode) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&left.hash);
        hasher.update(&right.hash);
        let hash = hasher.finalize().to_vec();

        MerkleNode {
            hash,
            nodetype: NodeType::Internal,
            value: None,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }
}

// A struct representing a Perfect Binary Merkle Tree, i.e., one storing 2^n leaves.
#[derive(Debug)]
struct PerfectMerkleTree {
    root: MerkleNode,
}

impl PerfectMerkleTree {
    fn new(data_blocks: Vec<&[u8]>) -> Self {
        let mut nodes = data_blocks
            .iter()
            .map(|&data| {
                MerkleNode::new_leaf(data.to_vec())
            })
            .collect::<Vec<_>>();

        while nodes.len() > 1 {
            if nodes.len() % 2 != 0 {
                // Throw an error
                panic!("Not a perfect binary tree! Odd number of nodes at some level ({})", nodes.len());
            }

            // Note: Do we actually need to clone the nodes?
            nodes = nodes
                .chunks(2)
                .map(|chunk| MerkleNode::from_children(chunk[1].clone(), chunk[0].clone()))
                .collect();
        }

        PerfectMerkleTree {
            root: nodes.into_iter().next().unwrap(),
        }
    }

    fn pretty_print(&self) {
        let mut stack = vec![(0, &self.root, "root".to_string())];
        while let Some((indent, node, label)) = stack.pop() {
            // println!("{}{}{}", " ".repeat(indent), hex_string(&node.hash), node.value.as_ref().map_or("".to_string(), |v| format!(" ({})", String::from_utf8_lossy(v))));
            // Include the label, hash and value in the output
            println!("{}[{}] {}{}", " ".repeat(indent), label, hex_string(&node.hash), node.value.as_ref().map_or("".to_string(), |v| format!(" ({})", String::from_utf8_lossy(v))));
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

/**
 * A struct representing a Merkle Forest, i.e., a collection of Perfect Merkle Trees.
 * Extends PerfectMerkleTree to support #leaves that are not a power of 2.
 * 
 * For example, if the total number of leaves is 133 or 10000101 in binary,
 * then we will have three PerfectMerkleTrees of leaves 2^0, 2^2 and 2^7 respectively.
 * In particular, trees[0] has 1 leaf, trees[2] has 4 leaves and trees[7] has 128 leaves.
 */
#[derive(Debug)]
pub struct MerkleForest {
    trees: Vec<Option<PerfectMerkleTree>>,
}

impl MerkleForest {
    pub fn new(mut entries: Vec<&[u8]>) -> Self {
        entries.reverse();
        let mut trees = vec![];
        let len = entries.len();        
        let mut i = 0;
        let mut j = len;
        while j > 0 {
            if j % 2 == 1 { // if ith bit of len is 1, then create a tree with 2^i leaves
                trees.push(Some(PerfectMerkleTree::new(
                    entries.drain(..(2usize.pow(i as u32))).collect::<Vec<_>>())
                ));
            } else {
                trees.push(None);
            }
            j /= 2;
            i += 1;
        }

        // We maintain an invariant that the last tree is always empty (makes it easy when adding elements later)
        if trees.is_empty() || trees.last().unwrap().is_some() {
            trees.push(None);
        }

        MerkleForest { trees }
    }

    pub fn add_entry(&mut self, entry: &[u8]) {
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

////// Helper functions 

// Print hash in hex format
fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect::<String>()
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
