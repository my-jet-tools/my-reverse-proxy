/// The settings file: on Windows what `--settings` names, otherwise `.my-reverse-proxy` in the
/// home directory.
pub fn settings_file_path() -> Result<String, String> {
    #[cfg(windows)]
    if let Some(settings_file) = super::explicit_settings_file() {
        return Ok(settings_file.file.clone());
    }

    Ok(format!("{}/.my-reverse-proxy", super::home_dir()?))
}

#[cfg(test)]
mod tests {
    use super::super::home_dir;
    use super::*;

    #[test]
    fn the_settings_file_is_in_the_home_directory() {
        assert_eq!(
            settings_file_path().unwrap(),
            format!("{}/.my-reverse-proxy", home_dir().unwrap())
        );
    }
}
