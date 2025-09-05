use merkle_forests::MerkleMountainRange;

fn main() {
    let data_blocks: Vec<&[u8]> = vec![b"block1", b"block2", b"block3"];

    println!("data_blocks: {:?}", data_blocks);

    let mut mmr = MerkleMountainRange::new(data_blocks);
    mmr.pretty_print();

    mmr.add_entry(b"block4");
    mmr.add_entry(b"block5");
    mmr.add_entry(b"block6");
    mmr.add_entry(b"block7");
    mmr.add_entry(b"block8");
    mmr.add_entry(b"block9");
    mmr.pretty_print();
}
