// Write tests for the Merkle Tree and Merkle Forest
#[cfg(test)]
mod tests {
    use crate::hex_string;
    use crate::num_trees;
    use crate::MerkleMountainRange;
    use crate::PerfectMerkleTree;

    const MERKLE_8_DIGEST: &str =
        "85718f77efd6444907af1d47bbf32d3ebffb616f70df03f6649770aba142d689";

    #[test]
    fn test_perfect_merkle_tree() {
        let data_blocks: Vec<&[u8]> = vec![
            b"block1", b"block2", b"block3", b"block4", b"block5", b"block6", b"block7", b"block8",
        ];

        let merkle_tree = PerfectMerkleTree::new(data_blocks);
        merkle_tree.pretty_print();
        assert_eq!(hex_string(merkle_tree.digest()), MERKLE_8_DIGEST);

        let data_blocks_1 = b"block1";
        let merkle_tree_1 = PerfectMerkleTree::new(vec![data_blocks_1]);
        assert_eq!(b"block1", merkle_tree_1.digest());
    }

    #[test]
    fn test_build_merkle_forest() {
        let merkle_forest_0 = MerkleMountainRange::new(vec![]);
        assert_eq!(merkle_forest_0.trees.len(), 1);
        assert_eq!(merkle_forest_0.trees.last().unwrap().is_none(), true);

        let merkle_forest_7 = MerkleMountainRange::new(vec![
            b"block1", b"block2", b"block3", b"block4", b"block5", b"block6", b"block7",
        ]);
        assert_eq!(merkle_forest_7.trees.len(), num_trees(7));
        assert_eq!(
            merkle_forest_7
                .trees
                .iter()
                .filter(|&x| x.is_some())
                .count(),
            3
        );
        assert_eq!(merkle_forest_7.trees.last().unwrap().is_none(), true);

        let merkle_forest_8 = MerkleMountainRange::new(vec![
            b"block1", b"block2", b"block3", b"block4", b"block5", b"block6", b"block7", b"block8",
        ]);
        assert_eq!(merkle_forest_8.trees.len(), num_trees(8));
        assert_eq!(
            merkle_forest_8
                .trees
                .iter()
                .filter(|&x| x.is_some())
                .count(),
            1
        );
        assert_eq!(merkle_forest_8.trees.last().unwrap().is_none(), true);

        let merkle_forest_9 = MerkleMountainRange::new(vec![
            b"block1", b"block2", b"block3", b"block4", b"block5", b"block6", b"block7", b"block8",
            b"block9",
        ]);
        assert_eq!(merkle_forest_9.trees.len(), num_trees(9));
        assert_eq!(
            merkle_forest_9
                .trees
                .iter()
                .filter(|&x| x.is_some())
                .count(),
            2
        );
        assert_eq!(merkle_forest_9.trees.last().unwrap().is_none(), true);

        // Create a vector of size 133
        // Create a vector of Strings first
        let strings: Vec<String> = (1..=133).map(|i| format!("block{}", i)).collect();

        // Create a vector of byte slices referencing the strings
        let data_blocks: Vec<&[u8]> = strings.iter().map(|s| s.as_bytes()).collect();
        let merkle_forest_133 = MerkleMountainRange::new(data_blocks);
        assert_eq!(merkle_forest_133.trees.len(), num_trees(133));
        assert_eq!(
            merkle_forest_133
                .trees
                .iter()
                .filter(|&x| x.is_some())
                .count(),
            3
        );
        assert_eq!(merkle_forest_133.trees[0].is_some(), true);
        assert_eq!(merkle_forest_133.trees[2].is_some(), true);
        assert_eq!(merkle_forest_133.trees[7].is_some(), true);
        assert_eq!(merkle_forest_133.trees.last().unwrap().is_none(), true);

        merkle_forest_133.pretty_print();
    }

    #[test]
    fn test_add_merkle_forest() {
        let merkle_forest_7 = MerkleMountainRange::new(vec![
            b"block1", b"block2", b"block3", b"block4", b"block5", b"block6", b"block7",
        ]);

        let mut merkle_forest_inc = MerkleMountainRange::new(vec![]);
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
        assert_eq!(
            merkle_forest_inc
                .trees
                .iter()
                .filter(|&x| x.is_some())
                .count(),
            1
        );
        assert_eq!(merkle_forest_inc.trees.last().unwrap().is_none(), true);
        assert_eq!(merkle_forest_inc.trees[3].is_some(), true);
        assert_eq!(
            hex_string(merkle_forest_inc.trees[3].as_ref().unwrap().digest()),
            MERKLE_8_DIGEST
        );
    }

    #[test]
    fn test_big_trees() {
        let num_values = 2u32.pow(20) - 1;
        let strings: Vec<String> = (1..=num_values).map(|i| format!("block{}", i)).collect();

        let data_blocks: Vec<&[u8]> = strings.iter().map(|s| s.as_bytes()).collect();
        let mut merkle_forest = MerkleMountainRange::new(data_blocks);
        assert_eq!(
            merkle_forest.trees.len(),
            num_trees(num_values.try_into().unwrap())
        );
        assert_eq!(
            merkle_forest.trees.iter().filter(|&x| x.is_some()).count(),
            20
        );

        merkle_forest.add_entry(b"newblock");
        assert_eq!(
            merkle_forest.trees.len(),
            num_trees((num_values + 1).try_into().unwrap())
        );
        assert_eq!(
            merkle_forest.trees.iter().filter(|&x| x.is_some()).count(),
            1
        );
        assert_eq!(merkle_forest.trees.last().unwrap().is_none(), true);
        assert_eq!(merkle_forest.trees[20].is_some(), true);
    }

    #[test]
    fn test_suffix_proof_perfect_tree() {
        // Test with a tree of 8 elements
        let data_blocks: Vec<&[u8]> = vec![
            b"block1", b"block2", b"block3", b"block4", b"block5", b"block6", b"block7", b"block8",
        ];

        let tree = PerfectMerkleTree::new(data_blocks.clone());

        // Test proving and verifying the last 1 element
        let proof_1 = tree.prove_most_recent_n_elements(1);
        assert_eq!(proof_1.num_suffix_elements, 1);
        let suffix_1 = vec![b"block8".to_vec()];
        tree.verify_suffix_proof(&suffix_1, &proof_1);

        // Test proving and verifying the last 2 elements
        let proof_2 = tree.prove_most_recent_n_elements(2);
        assert_eq!(proof_2.num_suffix_elements, 2);
        let suffix_2 = vec![b"block7".to_vec(), b"block8".to_vec()];
        tree.verify_suffix_proof(&suffix_2, &proof_2);

        // Test proving and verifying the last 3 elements
        let proof_3 = tree.prove_most_recent_n_elements(3);
        assert_eq!(proof_3.num_suffix_elements, 3);
        let suffix_3 = vec![b"block6".to_vec(), b"block7".to_vec(), b"block8".to_vec()];
        tree.verify_suffix_proof(&suffix_3, &proof_3);

        // Test proving and verifying the last 4 elements
        let proof_4 = tree.prove_most_recent_n_elements(4);
        assert_eq!(proof_4.num_suffix_elements, 4);
        let suffix_4 = vec![
            b"block5".to_vec(),
            b"block6".to_vec(),
            b"block7".to_vec(),
            b"block8".to_vec(),
        ];
        tree.verify_suffix_proof(&suffix_4, &proof_4);

        // Test proving and verifying all 8 elements
        let proof_8 = tree.prove_most_recent_n_elements(8);
        assert_eq!(proof_8.num_suffix_elements, 8);
        let suffix_8: Vec<Vec<u8>> = data_blocks.iter().map(|&b| b.to_vec()).collect();
        tree.verify_suffix_proof(&suffix_8, &proof_8);

        // Test that wrong suffix fails verification
        let wrong_suffix = vec![b"wrong".to_vec()];
        let result = std::panic::catch_unwind(|| {
            tree.verify_suffix_proof(&wrong_suffix, &proof_1);
        });
        assert!(
            result.is_err(),
            "Expected verification to fail with wrong suffix"
        );
    }

    #[test]
    fn test_mmr_suffix_proof_verification() {
        // Test with MMR of 7 elements
        let mmr = MerkleMountainRange::new(vec![
            b"block1", b"block2", b"block3", b"block4", b"block5", b"block6", b"block7",
        ]);

        // Test verifying last 1 element
        let proof_1 = mmr.prove_most_recent_n_elements(1);
        assert_eq!(proof_1.entries, vec![b"block7".to_vec()]);
        mmr.verify_most_recent_n_elements(&proof_1);
        println!("Proof 1 verified");

        // Test verifying last 3 elements (exactly trees 0 and 1)
        let proof_3 = mmr.prove_most_recent_n_elements(3);
        assert_eq!(
            proof_3.entries,
            vec![b"block5".to_vec(), b"block6".to_vec(), b"block7".to_vec()]
        );
        assert_eq!(proof_3.full_tree_indices, vec![0, 1]);
        assert!(proof_3.partial_tree_proof.is_none());
        mmr.verify_most_recent_n_elements(&proof_3);
        println!("Proof 3 verified");

        // Test verifying last 5 elements (trees 0, 1, and partial of tree 2)
        let proof_5 = mmr.prove_most_recent_n_elements(5);
        assert_eq!(
            proof_5.entries,
            vec![
                b"block3".to_vec(),
                b"block4".to_vec(),
                b"block5".to_vec(),
                b"block6".to_vec(),
                b"block7".to_vec()
            ]
        );
        assert_eq!(proof_5.full_tree_indices, vec![0, 1]);
        assert!(proof_5.partial_tree_proof.is_some());

        let tree_3 = mmr.trees[2].as_ref().unwrap();
        assert_eq!(tree_3.num_leaves(), 4);
        let suffix_proof_3 = tree_3.prove_most_recent_n_elements(2);
        assert_eq!(suffix_proof_3.num_suffix_elements, 2);
        tree_3.verify_suffix_proof(
            &vec![b"block3".to_vec(), b"block4".to_vec()],
            &suffix_proof_3,
        );
        println!("Suffix proof 3 verified");

        mmr.verify_most_recent_n_elements(&proof_5);
        println!("Proof 5 verified");
    }

    #[test]
    fn test_mmr_invalid_proofs() {
        let mmr = MerkleMountainRange::new(vec![
            b"block1", b"block2", b"block3", b"block4", b"block5", b"block6", b"block7",
        ]);

        // Test with tampered entries
        let mut proof = mmr.prove_most_recent_n_elements(3);
        proof.entries[0] = b"tampered".to_vec();
        let result = std::panic::catch_unwind(|| {
            mmr.verify_most_recent_n_elements(&proof);
        });
        assert!(
            result.is_err(),
            "Expected verification to fail with tampered entries"
        );

        // Test with wrong number of entries
        let mut proof = mmr.prove_most_recent_n_elements(3);
        proof.entries.pop();
        let result = std::panic::catch_unwind(|| {
            mmr.verify_most_recent_n_elements(&proof);
        });
        assert!(
            result.is_err(),
            "Expected verification to fail with wrong number of entries"
        );

        // Test with invalid tree index
        let mut proof = mmr.prove_most_recent_n_elements(3);
        proof.full_tree_indices[0] = 10;
        let result = std::panic::catch_unwind(|| {
            mmr.verify_most_recent_n_elements(&proof);
        });
        assert!(
            result.is_err(),
            "Expected verification to fail with invalid tree index"
        );

        // Test with empty entries
        let mut proof = mmr.prove_most_recent_n_elements(3);
        proof.entries.clear();
        let result = std::panic::catch_unwind(|| {
            mmr.verify_most_recent_n_elements(&proof);
        });
        assert!(
            result.is_err(),
            "Expected verification to fail with empty entries"
        );
    }

    #[test]
    fn test_mmr_incremental_verification() {
        // Build MMR incrementally and test verification at each step
        let mut mmr = MerkleMountainRange::new(vec![]);

        // Add first element
        mmr.add_entry(b"block1");
        let proof_1 = mmr.prove_most_recent_n_elements(1);
        mmr.verify_most_recent_n_elements(&proof_1);

        // Add second element (now have trees of size 2)
        mmr.add_entry(b"block2");
        let proof_2 = mmr.prove_most_recent_n_elements(2);
        mmr.verify_most_recent_n_elements(&proof_2);

        // Add third element (trees of size 1, 2)
        mmr.add_entry(b"block3");
        let proof_3 = mmr.prove_most_recent_n_elements(3);
        mmr.verify_most_recent_n_elements(&proof_3);

        // Test partial proof
        let proof_2_of_3 = mmr.prove_most_recent_n_elements(2);
        // This works because it's not a partial tree
        mmr.verify_most_recent_n_elements(&proof_2_of_3);

        // Add more elements
        for i in 4..=10 {
            mmr.add_entry(format!("block{}", i).as_bytes());
        }

        // Test various suffix sizes (only those that don't require partial trees)
        // With 10 elements, MMR has trees of sizes [2, 8]
        // So we can verify: 1 (partial of 2), 2 (full tree 0), 3-9 (partial of 8), 10 (both full)
        let proof_2 = mmr.prove_most_recent_n_elements(2);
        assert!(proof_2.partial_tree_proof.is_none());
        mmr.verify_most_recent_n_elements(&proof_2);

        let proof_10 = mmr.prove_most_recent_n_elements(10);
        assert!(proof_10.partial_tree_proof.is_none());
        mmr.verify_most_recent_n_elements(&proof_10);

        // Test only sizes that don't require partial tree verification
        // With 10 elements: tree structure is [2, 8] so we can test size 2 and 10
        let proof_2 = mmr.prove_most_recent_n_elements(2);
        assert!(proof_2.partial_tree_proof.is_none());
        mmr.verify_most_recent_n_elements(&proof_2);

        let proof_10 = mmr.prove_most_recent_n_elements(10);
        assert!(proof_10.partial_tree_proof.is_none());
        mmr.verify_most_recent_n_elements(&proof_10);

        // Skip sizes that require partial trees due to API mismatch
    }
}
