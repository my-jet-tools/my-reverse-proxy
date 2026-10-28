/// The home directory: the folder the settings file is read from, and what a leading `~` of a
/// path stands for. On Windows it is the folder of the file `--settings` names, when the command
/// line names one; otherwise `HOME` when that is set - to anything, so a second instance is
/// started by pointing `HOME` somewhere else - and otherwise, on Windows, which does not set
/// `HOME`, `USERPROFILE`.
pub fn home_dir() -> Result<String, String> {
    #[cfg(windows)]
    if let Some(settings_file) = super::explicit_settings_file() {
        return Ok(settings_file.dir.clone());
    }

    #[cfg(windows)]
    let fallback = Some(("USERPROFILE", std::env::var("USERPROFILE").ok()));
    #[cfg(not(windows))]
    let fallback = None;

    home_dir_of(std::env::var("HOME").ok(), fallback)
}

/// The decision of `home_dir` on the values of the variables. `fallback` is the variable which is
/// read when `HOME` is not set, with its value - there is none but on Windows.
fn home_dir_of(
    home: Option<String>,
    fallback: Option<(&str, Option<String>)>,
) -> Result<String, String> {
    if let Some(home) = home {
        return Ok(home);
    }

    let not_set = match fallback {
        Some((_, Some(home))) => return Ok(home),
        Some((name, None)) => format!("neither HOME nor {name} is set"),
        None => "HOME is not set".to_string(),
    };

    // `--settings` is an option of the Windows command line only.
    #[cfg(windows)]
    let or_name_the_file = ", or name the file with --settings <file>";
    #[cfg(not(windows))]
    let or_name_the_file = "";

    Err(format!(
        "The home directory is not known: {not_set}. The settings file .my-reverse-proxy is read from the home directory - set HOME to the folder which holds it{or_name_the_file}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_is_taken_over_user_profile() {
        let home = home_dir_of(
            Some("/srv/proxy-b".to_string()),
            Some(("USERPROFILE", Some(r"C:\Users\proxy".to_string()))),
        );

        assert_eq!(home.unwrap(), "/srv/proxy-b");
    }

    #[test]
    fn an_empty_home_is_still_the_home_directory() {
        let home = home_dir_of(
            Some(String::new()),
            Some(("USERPROFILE", Some(r"C:\Users\proxy".to_string()))),
        );

        assert_eq!(home.unwrap(), "");
    }

    #[test]
    fn user_profile_is_the_home_directory_when_home_is_not_set() {
        let home = home_dir_of(
            None,
            Some(("USERPROFILE", Some(r"C:\Users\proxy".to_string()))),
        );

        assert_eq!(home.unwrap(), r"C:\Users\proxy");
    }

    #[test]
    fn neither_home_nor_user_profile_is_an_error_which_names_both() {
        let err = home_dir_of(None, Some(("USERPROFILE", None))).unwrap_err();

        assert!(err.contains("neither HOME nor USERPROFILE is set"), "{err}");
        assert!(err.contains(".my-reverse-proxy"), "{err}");
    }

    #[test]
    fn no_home_without_a_fallback_is_an_error_which_names_only_home() {
        let err = home_dir_of(None, None).unwrap_err();

        assert!(err.contains("HOME is not set"), "{err}");
        assert!(!err.contains("USERPROFILE"), "{err}");
        assert!(err.contains(".my-reverse-proxy"), "{err}");
    }
}
