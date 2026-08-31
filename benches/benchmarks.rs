/// Criterion benchmarks for the plog-core hot paths.
///
/// Run with:
///   cargo bench
///
/// Benchmarks cover:
///   1. hex::decode — small / medium / large / with-whitespace packets
///   2. Extractor (regex) — matching and non-matching lines
///   3. End-to-end pipeline — synthetic in-memory "log" written to a temp file

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use plog_core::extractor::Extractor;
use plog_core::hex;
use std::io::Write;
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_hex_string(byte_count: usize) -> String {
    let nibbles: Vec<u8> = (0u8..16).cycle().take(byte_count).collect();
    nibbles.iter().map(|n| format!("{:x}", n)).collect()
}

fn make_hex_string_with_spaces(byte_count: usize) -> String {
    let mut s = String::with_capacity(byte_count * 3);
    for i in 0..byte_count {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{:02x}", (i % 256) as u8));
    }
    s
}

// ---------------------------------------------------------------------------
// 1. Hex decoding benchmarks
// ---------------------------------------------------------------------------

fn bench_hex_decode(c: &mut Criterion) {
    let sizes = [
        ("small_16B", 16usize),
        ("medium_128B", 128),
        ("large_2KB", 2048),
    ];

    let mut group = c.benchmark_group("hex_decode");
    for (label, size) in &sizes {
        let hex = make_hex_string(*size);
        group.throughput(Throughput::Bytes((*size) as u64));
        group.bench_with_input(BenchmarkId::new("compact", label), &hex, |b, h| {
            b.iter(|| hex::decode(black_box(h)).unwrap())
        });

        let hex_spaced = make_hex_string_with_spaces(*size);
        group.bench_with_input(BenchmarkId::new("spaced", label), &hex_spaced, |b, h| {
            b.iter(|| hex::decode(black_box(h)).unwrap())
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// 2. Regex extraction benchmarks
// ---------------------------------------------------------------------------

fn bench_extractor(c: &mut Criterion) {
    let pattern = r"PACKET: (?P<hex>[0-9a-fA-F ]+)";
    let extractor = Extractor::new(pattern).unwrap();

    let matching_line =
        "2024-01-01T12:00:00 [INFO] PACKET: deadbeef cafebabe 01020304 deadbeef";
    let non_matching_line = "2024-01-01T12:00:00 [INFO] some other log message here";

    let mut group = c.benchmark_group("extractor");
    group.bench_function("matching_line", |b| {
        b.iter(|| extractor.extract_from_line(black_box(matching_line)))
    });
    group.bench_function("non_matching_line", |b| {
        b.iter(|| extractor.extract_from_line(black_box(non_matching_line)))
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// 3. End-to-end pipeline benchmark (via temp file)
// ---------------------------------------------------------------------------

fn bench_pipeline(c: &mut Criterion) {
    use plog_core::pipeline::{start_analysis, AnalysisConfig, AnalysisEvent};

    let packet_hex = make_hex_string(64); // 64-byte packets

    // Build log variants: 1 000 lines and 10 000 lines
    for line_count in [1_000usize, 10_000] {
        let mut f = NamedTempFile::new().unwrap();
        for i in 0..line_count {
            if i % 5 == 0 {
                writeln!(f, "2024-01-01 PACKET: {}", packet_hex).unwrap();
            } else {
                writeln!(f, "2024-01-01 [INFO] log line number {}", i).unwrap();
            }
        }
        f.flush().unwrap();

        let path = f.path().to_path_buf();
        let label = format!("{}_lines", line_count);

        c.bench_function(&format!("pipeline_{}", label), |b| {
            b.iter(|| {
                let config = AnalysisConfig {
                    pattern: r"PACKET: (?P<hex>[0-9a-fA-F ]+)".to_string(),
                    ksy_source: "name: bench".to_string(),
                };
                let rx = start_analysis(path.clone(), config).unwrap();
                let mut count = 0u64;
                for event in rx {
                    if let AnalysisEvent::Packet(_) = event {
                        count += 1;
                    }
                }
                black_box(count)
            })
        });
    }
}

// ---------------------------------------------------------------------------

criterion_group!(benches, bench_hex_decode, bench_extractor, bench_pipeline);
criterion_main!(benches);
