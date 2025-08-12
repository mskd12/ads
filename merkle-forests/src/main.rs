use merkle_forests::MerkleForest;

fn main() {
    let data_blocks: Vec<&[u8]> = vec![
        b"block1", 
        b"block2", 
        b"block3", 
    ];

    let mut merkle_tree = MerkleForest::new(data_blocks);
    // println!("Merkle Tree Root Hash: {:?}", &merkle_tree.digest());
    // merkle_tree.pretty_print();

    merkle_tree.add_entry(b"block4");
    // println!("Merkle Tree Root Hash: {:?}", &merkle_tree.digest());
    // merkle_tree.pretty_print();

    merkle_tree.add_entry(b"block5");
    merkle_tree.add_entry(b"block6");
    merkle_tree.add_entry(b"block7");
    merkle_tree.add_entry(b"block8");
    merkle_tree.add_entry(b"block9");
    merkle_tree.pretty_print();
}
