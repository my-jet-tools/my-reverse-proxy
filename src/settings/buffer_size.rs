/// Parses a human-friendly buffer-size value: a raw byte count, or a number
/// suffixed with `Kb` / `Mb` / `Gb` (e.g. `512Kb`, `1Mb`, `2Gb`).
///
/// A size too large for a `usize` is an error, not a smaller size: the multiplication is checked.
pub fn parse_buffer_size(value: &str) -> Result<usize, String> {
    let on_err = |err: std::num::ParseIntError| {
        format!(
            "Can not parse buffer size value: '{}'. Error: {}",
            value, err
        )
    };

    let (number, unit) = if let Some(gb) = value.strip_suffix("Gb") {
        (gb.trim(), 1024 * 1024 * 1024)
    } else if let Some(mb) = value.strip_suffix("Mb") {
        (mb.trim(), 1024 * 1024)
    } else if let Some(kb) = value.strip_suffix("Kb") {
        (kb.trim(), 1024)
    } else {
        (value, 1)
    };

    let number = number.parse::<usize>().map_err(on_err)?;

    number
        .checked_mul(unit)
        .ok_or_else(|| format!("Buffer size value is too large: '{}'", value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_size_is_bytes_or_a_number_of_kb_mb_gb() {
        assert_eq!(parse_buffer_size("1000"), Ok(1000));
        assert_eq!(parse_buffer_size("512Kb"), Ok(512 * 1024));
        assert_eq!(parse_buffer_size("1Mb"), Ok(1024 * 1024));
        assert_eq!(parse_buffer_size("2 Gb"), Ok(2 * 1024 * 1024 * 1024));
    }

    #[test]
    fn a_size_which_does_not_fit_is_an_error_not_a_smaller_size() {
        let err = parse_buffer_size("18446744073709551615Gb").unwrap_err();
        assert!(err.contains("too large"), "{err}");

        assert!(parse_buffer_size("10 MB").is_err());
        assert!(parse_buffer_size("").is_err());
    }
}
