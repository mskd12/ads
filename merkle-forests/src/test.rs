// Write tests for the Merkle Tree and Merkle Forest
#[cfg(test)]
mod tests {
    use crate::PerfectMerkleTree;
    use crate::MerkleForest;
    use crate::num_trees;
    use crate::hex_string;
    use sha2::Digest;

    const MERKLE_8_DIGEST: &str = "559de5deb10ccf1fff1d1096e2e1dffccf15727374bf2bf3afebbc22005bf999";

    #[test]
    fn test_perfect_merkle_tree() {
        let data_blocks: Vec<&[u8]> = vec![
            b"block8", 
            b"block7", 
            b"block6", 
            b"block5",
            b"block4",
            b"block3",
            b"block2",
            b"block1",
        ];

        let merkle_tree = PerfectMerkleTree::new(data_blocks);
        merkle_tree.pretty_print();
        assert_eq!(hex_string(merkle_tree.digest()), MERKLE_8_DIGEST);

        let data_blocks_1 = b"block1";
        let merkle_tree_1 = PerfectMerkleTree::new(vec![data_blocks_1]);
        assert_eq!(sha2::Sha256::digest(b"block1").to_vec(), merkle_tree_1.digest());
    }

    #[test]
    fn test_build_merkle_forest() {
        let merkle_forest_0 = MerkleForest::new(vec![]);
        assert_eq!(merkle_forest_0.trees.len(), 1);
        assert_eq!(merkle_forest_0.trees.last().unwrap().is_none(), true);

        let merkle_forest_7 = MerkleForest::new(vec![
            b"block1", 
            b"block2", 
            b"block3", 
            b"block4",
            b"block5",
            b"block6",
            b"block7",
        ]);
        assert_eq!(merkle_forest_7.trees.len(), num_trees(7));
        assert_eq!(merkle_forest_7.trees.iter().filter(|&x| x.is_some()).count(), 3);
        assert_eq!(merkle_forest_7.trees.last().unwrap().is_none(), true);

        let merkle_forest_8 = MerkleForest::new(vec![
            b"block1", 
            b"block2", 
            b"block3", 
            b"block4",
            b"block5",
            b"block6",
            b"block7",
            b"block8",
        ]);
        assert_eq!(merkle_forest_8.trees.len(), num_trees(8));
        assert_eq!(merkle_forest_8.trees.iter().filter(|&x| x.is_some()).count(), 1);
        assert_eq!(merkle_forest_8.trees.last().unwrap().is_none(), true);

        let merkle_forest_9 = MerkleForest::new(vec![
            b"block1", 
            b"block2", 
            b"block3", 
            b"block4",
            b"block5",
            b"block6",
            b"block7",
            b"block8",
            b"block9",
        ]);
        assert_eq!(merkle_forest_9.trees.len(), num_trees(9));
        assert_eq!(merkle_forest_9.trees.iter().filter(|&x| x.is_some()).count(), 2);
        assert_eq!(merkle_forest_9.trees.last().unwrap().is_none(), true);

        // Create a vector of size 133
        // Create a vector of Strings first
        let strings: Vec<String> = (1..=133)
            .map(|i| format!("block{}", i))
            .collect();

        // Create a vector of byte slices referencing the strings
        let data_blocks: Vec<&[u8]> = strings.iter()
            .map(|s| s.as_bytes())
            .collect();
        let merkle_forest_133 = MerkleForest::new(data_blocks);
        assert_eq!(merkle_forest_133.trees.len(), num_trees(133));
        assert_eq!(merkle_forest_133.trees.iter().filter(|&x| x.is_some()).count(), 3);
        assert_eq!(merkle_forest_133.trees[0].is_some(), true);
        assert_eq!(merkle_forest_133.trees[2].is_some(), true);
        assert_eq!(merkle_forest_133.trees[7].is_some(), true);
        assert_eq!(merkle_forest_133.trees.last().unwrap().is_none(), true);

        merkle_forest_133.pretty_print();
    }

    #[test]
    fn test_add_merkle_forest() {
        let merkle_forest_7 = MerkleForest::new(vec![
            b"block1", 
            b"block2", 
            b"block3", 
            b"block4",
            b"block5",
            b"block6",
            b"block7",
        ]);

        let mut merkle_forest_inc = MerkleForest::new(vec![]);
        merkle_forest_inc.add_entry(b"block1");
        merkle_forest_inc.add_entry(b"block2");
        merkle_forest_inc.add_entry(b"block3");
        merkle_forest_inc.add_entry(b"block4");
        merkle_forest_inc.add_entry(b"block5");
        merkle_forest_inc.add_entry(b"block6");
        merkle_forest_inc.add_entry(b"block7");

        assert_eq!(merkle_forest_7.digests(), merkle_forest_inc.digests());

        merkle_forest_inc.add_entry(b"block8");
        merkle_forest_inc.pretty_print();
        assert_eq!(merkle_forest_inc.trees.len(), num_trees(8));
        assert_eq!(merkle_forest_inc.trees.iter().filter(|&x| x.is_some()).count(), 1);
        assert_eq!(merkle_forest_inc.trees.last().unwrap().is_none(), true);
        assert_eq!(merkle_forest_inc.trees[3].is_some(), true);
        assert_eq!(hex_string(merkle_forest_inc.trees[3].as_ref().unwrap().digest()), MERKLE_8_DIGEST);
    }

    #[test]
    fn test_big_trees() {
        let num_values = 2u32.pow(20) - 1;
        let strings: Vec<String> = (1..=num_values)
            .map(|i| format!("block{}", i))
            .collect();

        let data_blocks: Vec<&[u8]> = strings.iter()
            .map(|s| s.as_bytes())
            .collect();
        let mut merkle_forest = MerkleForest::new(data_blocks);
        assert_eq!(merkle_forest.trees.len(), num_trees(num_values.try_into().unwrap()));
        assert_eq!(merkle_forest.trees.iter().filter(|&x| x.is_some()).count(), 20);

        merkle_forest.add_entry(b"newblock");
        assert_eq!(merkle_forest.trees.len(), num_trees((num_values + 1).try_into().unwrap()));
        assert_eq!(merkle_forest.trees.iter().filter(|&x| x.is_some()).count(), 1);
        assert_eq!(merkle_forest.trees.last().unwrap().is_none(), true);
        assert_eq!(merkle_forest.trees[20].is_some(), true);
    }
}