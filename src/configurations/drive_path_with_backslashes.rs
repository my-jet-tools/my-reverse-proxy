use std::borrow::Cow;

/// A local file source the way `RemoteEndpoint` can read it. On Windows a path which starts with a
/// drive is a local path however its separators are written, but `RemoteEndpoint` reads the `C`
/// of `C:/certs/a.pem` as a scheme and refuses it, while `C:\certs\a.pem` is a path to it - so the
/// `/` of a drive path are turned into `\`. Anything else, and on other systems everything, is
/// kept as it is.
pub fn drive_path_with_backslashes(src: &str) -> Cow<'_, str> {
    #[cfg(windows)]
    if is_drive_path(src) {
        return Cow::Owned(src.replace('/', "\\"));
    }

    Cow::Borrowed(src)
}

/// An ASCII letter, a `:` and a separator: `C:\...` or `C:/...`.
#[cfg(windows)]
fn is_drive_path(src: &str) -> bool {
    matches!(src.as_bytes(), [drive, b':', b'/' | b'\\', ..] if drive.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn a_drive_path_written_with_slashes_gets_backslashes() {
        assert_eq!(
            drive_path_with_backslashes("C:/certs/a.pem"),
            r"C:\certs\a.pem"
        );
        assert_eq!(
            drive_path_with_backslashes(r"d:\certs/a.pem"),
            r"d:\certs\a.pem"
        );
        assert_eq!(
            drive_path_with_backslashes(r"C:\certs\a.pem"),
            r"C:\certs\a.pem"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_path_without_a_drive_is_kept_on_windows() {
        for src in [
            "/srv/www",
            "~/certs/a.pem",
            "http://localhost:8000/a.pem",
            "C:",
            "C:www",
            "CC:/www",
            "1:/www",
            "",
        ] {
            assert_eq!(drive_path_with_backslashes(src), src);
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn a_drive_path_is_kept_off_windows() {
        assert_eq!(
            drive_path_with_backslashes("C:/certs/a.pem"),
            "C:/certs/a.pem"
        );
    }
}
