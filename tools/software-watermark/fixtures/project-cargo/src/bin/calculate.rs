// SPDX-License-Identifier: MPL-2.0
use fileveil_real_cargo_acceptance::{calculate, parsed_count};
fn main() {
    let input = std::env::args().nth(1).unwrap_or_else(|| "1000".into());
    let count = parsed_count(&input).unwrap();
    assert!(count <= 1_000_000);
    println!("{}", calculate(count));
}
