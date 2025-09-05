use criterion::{black_box, criterion_group, criterion_main, Criterion};
use merkle_forests::MerkleMountainRange;

fn bench_merkle_tree_creation(c: &mut Criterion) {
    let lengths = vec![100, 1000, 10000];
    for length in lengths {
        // Create a vector of different data blocks
        let strings: Vec<String> = (1..=length).map(|i| format!("block{}", i)).collect();
        let data_blocks: Vec<&[u8]> = strings.iter().map(|s| s.as_bytes()).collect();

        c.bench_function(format!("merkle_tree_creation_{}", length).as_str(), |b| {
            b.iter(|| {
                black_box(MerkleMountainRange::new(data_blocks.clone()));
            })
        });
    }
}

fn bench_merkle_tree_add_entry(c: &mut Criterion) {
    let lengths = vec![
        2u32.pow(5) - 1,
        2u32.pow(10) - 1,
        2u32.pow(15) - 1,
        2u32.pow(20) - 1,
    ];
    for length in lengths {
        // Create a vector of different data blocks
        let strings: Vec<String> = (1..=length).map(|i| format!("block{}", i)).collect();
        let data_blocks: Vec<&[u8]> = strings.iter().map(|s| s.as_bytes()).collect();
        let mut merkle_tree = MerkleMountainRange::new(data_blocks);

        c.bench_function(format!("merkle_tree_add_entry_{}", length).as_str(), |b| {
            b.iter(|| {
                black_box(merkle_tree.add_entry(b"newblock"));
            })
        });
    }
}

criterion_group!(benches, bench_merkle_tree_add_entry);

criterion_main!(benches);
