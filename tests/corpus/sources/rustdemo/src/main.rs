fn collatz(mut n: u64) -> u64 {
    let mut steps = 0u64;
    while n != 1 {
        if n % 2 == 0 { n /= 2; } else { n = 3 * n + 1; }
        steps += 1;
    }
    steps
}

fn fib(n: u64) -> u64 {
    if n < 2 { return n; }
    let (mut a, mut b) = (0u64, 1u64);
    for _ in 0..n { let t = a + b; a = b; b = t; }
    a
}

fn main() {
    let n: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(10);
    println!("fib={} collatz={}", fib(n), collatz(n));
}
