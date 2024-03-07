use std::{collections::LinkedList, sync::Arc, thread::spawn};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use open_rdma_driver::{
    scheduler::{
        bench::{generate_big_descriptor, generate_random_descriptors},
        split_descriptor,
    },
    scheduler::{round_robin::RoundRobinStrategy, SchedulerStrategy},
    ToCardWorkRbDesc,
};
use rand::{thread_rng, Rng};

fn bench_push_descriptors(descriptors: LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)>) {
    let strat = RoundRobinStrategy::new();
    for (qpn, descriptor_list) in descriptors {
        strat.push(qpn, descriptor_list);
    }
}

fn bench_push_and_pop_descriptors(descriptors: LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)>) {
    let length = descriptors.len();
    let strat = Arc::new(RoundRobinStrategy::new());
    let thread_strat = Arc::clone(&strat);
    let handler = spawn(move || {
        let mut counter = 0;
        loop {
            if let Some(_desc) = thread_strat.pop() {
                counter += 1;
                if counter == length {
                    return;
                }
            }
        }
    });
    for (qpn, descriptor_list) in descriptors {
        strat.push(qpn, descriptor_list);
    }
    handler.join().unwrap();
}

fn criterion_slice_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("split");
    group.bench_function(BenchmarkId::new("bench_split", "1G"), |b| {
        b.iter_batched(
            || -> ToCardWorkRbDesc {
                let size = 1024 * 1024 * 1024;
                black_box(generate_big_descriptor(size))
            },
            split_descriptor,
            criterion::BatchSize::LargeInput,
        );
    });
    group.bench_function(BenchmarkId::new("bench_split", "100M"), |b| {
        b.iter_batched(
            || -> ToCardWorkRbDesc {
                let size = 1024*1024*100;
                black_box(generate_big_descriptor(size))
            },
            split_descriptor,
            criterion::BatchSize::LargeInput,
        );
    });
    group.bench_function(BenchmarkId::new("bench_split", "10M"), |b| {
        b.iter_batched(
            || -> ToCardWorkRbDesc {
                let size = 1024*1024*10;
                black_box(generate_big_descriptor(size))
            },
            split_descriptor,
            criterion::BatchSize::LargeInput,
        );
    });
    group.bench_function(BenchmarkId::new("bench_split", "1M"), |b| {
        b.iter_batched(
            || -> ToCardWorkRbDesc {
                let size = 1024 * 1024;
                black_box(generate_big_descriptor(size))
            },
            split_descriptor,
            criterion::BatchSize::LargeInput,
        );
    });
    group.finish();
}

fn criterion_push_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("push");
    group.bench_function(BenchmarkId::new("bench_push", "4096000*1"), |b| {
        b.iter_batched(
            || -> LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> {
                let mut descriptors: LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> =
                    LinkedList::new();
                let number_of_desc_list = 4096000;
                let mut rng = thread_rng();
                for _ in 0..number_of_desc_list {
                    let qpn = rng.gen_range(0..10);
                    let num = 1;
                    descriptors.push_back((qpn, generate_random_descriptors(qpn, num)));
                }
                black_box(descriptors)
            },
            bench_push_descriptors,
            criterion::BatchSize::LargeInput,
        );
    });

    group.bench_function(BenchmarkId::new("bench_push", "100000*40"), |b| {
        b.iter_batched(
            || -> LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> {
                let mut descriptors: LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> =
                    LinkedList::new();
                let number_of_desc_list = 100000;
                let mut rng = thread_rng();
                for _ in 0..number_of_desc_list {
                    let qpn = rng.gen_range(0..10);
                    let num = 40;
                    descriptors.push_back((qpn, generate_random_descriptors(qpn, num)));
                }
                black_box(descriptors)
            },
            bench_push_descriptors,
            criterion::BatchSize::LargeInput,
        );
    });

    group.bench_function(BenchmarkId::new("bench_push", "10000*410"), |b| {
        b.iter_batched(
            || -> LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> {
                let mut descriptors: LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> =
                    LinkedList::new();
                let number_of_desc_list = 10000;
                let mut rng = thread_rng();
                for _ in 0..number_of_desc_list {
                    let qpn = rng.gen_range(0..10);
                    let num = 410;
                    descriptors.push_back((qpn, generate_random_descriptors(qpn, num)));
                }
                black_box(descriptors)
            },
            bench_push_descriptors,
            criterion::BatchSize::LargeInput,
        );
    });

    group.bench_function(BenchmarkId::new("bench_push", "1000*4096"), |b| {
        b.iter_batched(
            || -> LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> {
                let mut descriptors: LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> =
                    LinkedList::new();
                let number_of_desc_list = 1000;
                let mut rng = thread_rng();
                for _ in 0..number_of_desc_list {
                    let qpn = rng.gen_range(0..10);
                    let num = 4096;
                    descriptors.push_back((qpn, generate_random_descriptors(qpn, num)));
                }
                black_box(descriptors)
            },
            bench_push_descriptors,
            criterion::BatchSize::LargeInput,
        );
    });

    group.bench_function(BenchmarkId::new("bench_push", "100000*40,qpn=0..100"), |b| {
        b.iter_batched(
            || -> LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> {
                let mut descriptors: LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> =
                    LinkedList::new();
                let number_of_desc_list = 100000;
                let mut rng = thread_rng();
                for _ in 0..number_of_desc_list {
                    let qpn = rng.gen_range(0..100);
                    let num = 40;
                    descriptors.push_back((qpn, generate_random_descriptors(qpn, num)));
                }
                black_box(descriptors)
            },
            bench_push_descriptors,
            criterion::BatchSize::LargeInput,
        );
    });

    group.bench_function(BenchmarkId::new("bench_push", "100000*40,qpn=0..1000"), |b| {
        b.iter_batched(
            || -> LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> {
                let mut descriptors: LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> =
                    LinkedList::new();
                let number_of_desc_list = 100000;
                let mut rng = thread_rng();
                for _ in 0..number_of_desc_list {
                    let qpn = rng.gen_range(0..1000);
                    let num = 40;
                    descriptors.push_back((qpn, generate_random_descriptors(qpn, num)));
                }
                black_box(descriptors)
            },
            bench_push_descriptors,
            criterion::BatchSize::LargeInput,
        );
    });
    
    group.finish();
}

// bench the delay of the push function
fn criterion_push_delay_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("push");
    group.bench_function(BenchmarkId::new("bench_push_delay", "1000*4096"), |b| {
        b.iter_batched(
            || -> LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> {
                let mut descriptors: LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> =
                    LinkedList::new();
                let number_of_desc_list = 1000;
                let mut rng = thread_rng();
                for _ in 0..number_of_desc_list {
                    let qpn = rng.gen_range(0..10);
                    let num = 4096;
                    descriptors.push_back((qpn, generate_random_descriptors(qpn, num)));
                }
                black_box(descriptors)
            },
            bench_push_and_pop_descriptors,
            criterion::BatchSize::LargeInput,
        );
    });
    group.bench_function(BenchmarkId::new("bench_push_delay", "10000*410"), |b| {
        b.iter_batched(
            || -> LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> {
                let mut descriptors: LinkedList<(u32, LinkedList<ToCardWorkRbDesc>)> =
                    LinkedList::new();
                let number_of_desc_list = 1000;
                let mut rng = thread_rng();
                for _ in 0..number_of_desc_list {
                    let qpn = rng.gen_range(0..10);
                    let num = 4096;
                    descriptors.push_back((qpn, generate_random_descriptors(qpn, num)));
                }
                black_box(descriptors)
            },
            bench_push_and_pop_descriptors,
            criterion::BatchSize::LargeInput,
        );
    });
    group.finish();
}

criterion_group! {
    name = benches;
    // This can be any expression that returns a `Criterion` object.
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = criterion_push_benchmark,criterion_push_delay_benchmark,criterion_slice_benchmark
}

criterion_main!(benches);
