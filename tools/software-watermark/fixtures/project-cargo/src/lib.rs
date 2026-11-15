// SPDX-License-Identifier: MPL-2.0
pub fn calculate(count: u64) -> u64 {
    (1..=count).sum()
}
pub fn parsed_count(input: &str) -> Result<u64, serde_json::Error> {
    serde_json::from_str(input)
}
#[cfg(test)]
mod tests {
    #[test]
    fn dependency_and_arithmetic() {
        for (input, expected) in [("0", 0), ("10", 55), ("1000", 500500)] {
            let n = super::parsed_count(input).unwrap();
            assert_eq!(super::calculate(n), expected);
        }
        assert!(super::parsed_count("not-json").is_err());
    }
}
