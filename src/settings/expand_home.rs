/// A leading `~`, alone or followed by a `/` or a `\`, is the home directory. It is the rule the
/// path helper of `rust_extensions::file_utils` follows, with the home directory of `home_dir`,
/// and with an error instead of the path as it is when that is not known. A `~` anywhere else
/// (`~user/x`, `/srv/~x`, `x~`) is a part of a name and is kept, so a path without a leading `~`
/// never needs the home directory and is never an error.
pub fn expand_home(path: &str) -> Result<String, String> {
    let Some(rest) = path.strip_prefix('~') else {
        return Ok(path.to_string());
    };

    if !(rest.is_empty() || rest.starts_with('/') || rest.starts_with('\\')) {
        return Ok(path.to_string());
    }

    let home = super::home_dir().map_err(|err| format!("Can not expand the ~ of {path}: {err}"))?;

    Ok(format!("{home}{rest}"))
}

#[cfg(test)]
mod tests {
    use super::super::home_dir;
    use super::*;

    #[test]
    fn a_leading_tilde_is_the_home_directory() {
        let home = home_dir().unwrap();

        assert_eq!(expand_home("~").unwrap(), home);
        assert_eq!(expand_home("~/a").unwrap(), format!("{home}/a"));
        assert_eq!(expand_home(r"~\a").unwrap(), format!(r"{home}\a"));
    }

    #[test]
    fn only_the_leading_tilde_is_expanded() {
        let home = home_dir().unwrap();

        assert_eq!(expand_home("~/a~b").unwrap(), format!("{home}/a~b"));
    }

    #[test]
    fn a_tilde_which_is_a_part_of_a_name_is_kept() {
        for path in ["~user/a", "/srv/~a", "a~", ""] {
            assert_eq!(expand_home(path).unwrap(), path);
        }
    }
}
