//! The settings file named on the command line, `--settings <file>`. It is read instead of
//! `~/.my-reverse-proxy`, and its folder is the home directory - what a leading `~` of a path in
//! the settings stands for. One argument tells an installed Windows service where everything is:
//! a service runs as LocalSystem, whose profile folder is not where anybody keeps a settings file.
//!
//! Set once by `main`, before the settings are read; `settings_file_path` and `home_dir` look
//! here first.

use std::sync::OnceLock;

pub struct ExplicitSettingsFile {
    /// The file, as an absolute path.
    pub file: String,
    /// Its folder - the home directory while this is the settings file.
    pub dir: String,
}

static EXPLICIT_SETTINGS_FILE: OnceLock<ExplicitSettingsFile> = OnceLock::new();

/// Names the settings file for the rest of the process. The file has to exist: a wrong path is
/// found out here, before anything else starts.
pub fn set_settings_file(path: &str) -> Result<(), String> {
    let absolute = std::path::absolute(path)
        .map_err(|err| format!("Can not resolve the settings file path {path}: {err}"))?;

    let location = explicit_settings_file_of(absolute.to_string_lossy().as_ref())?;

    if !std::path::Path::new(location.file.as_str()).is_file() {
        return Err(format!(
            "The settings file {} does not exist",
            location.file
        ));
    }

    EXPLICIT_SETTINGS_FILE
        .set(location)
        .map_err(|_| "The settings file is named once".to_string())
}

pub fn explicit_settings_file() -> Option<&'static ExplicitSettingsFile> {
    EXPLICIT_SETTINGS_FILE.get()
}

/// The file and its folder, of an absolute path. The verbatim prefix of Windows is taken off
/// first: `canonicalize` - which `--install` runs the path through before it is written into the
/// command line of the service - gives `\\?\C:\proxy\settings.yaml`, and Win32 does not normalize
/// a verbatim path, so the `\\?\C:\proxy/.my-reverse-proxy-dynamic` which `~/` would make of its
/// folder does not open.
fn explicit_settings_file_of(absolute: &str) -> Result<ExplicitSettingsFile, String> {
    let file = strip_verbatim_prefix(absolute);

    let dir = parent_folder(file.as_str())
        .ok_or_else(|| format!("The settings file {file} is not a file in a folder"))?
        .to_string();

    Ok(ExplicitSettingsFile { file, dir })
}

/// `\\?\C:\x` is `C:\x` and `\\?\UNC\server\share\x` is `\\server\share\x`; any other path is
/// kept.
fn strip_verbatim_prefix(path: &str) -> String {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }

    if let Some(rest) = path.strip_prefix(r"\\?\") {
        let mut chars = rest.chars();
        let is_drive_path = matches!(
            (chars.next(), chars.next()),
            (Some(drive), Some(':')) if drive.is_ascii_alphabetic()
        );

        if is_drive_path {
            return rest.to_string();
        }
    }

    path.to_string()
}

/// The folder of a path, with `/` and `\` both taken as separators - a Windows path is written
/// either way. The root folder is kept as the separator: `/x` is in `/`.
fn parent_folder(path: &str) -> Option<&str> {
    let separator = path.rfind(['/', '\\'])?;

    if separator == 0 {
        return Some(&path[..1]);
    }

    Some(&path[..separator])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_folder_of_the_settings_file_is_the_home_directory() {
        let location = explicit_settings_file_of(r"C:\proxy\settings.yaml").unwrap();
        assert_eq!(location.file, r"C:\proxy\settings.yaml");
        assert_eq!(location.dir, r"C:\proxy");

        let location = explicit_settings_file_of("/srv/proxy-b/settings.yaml").unwrap();
        assert_eq!(location.file, "/srv/proxy-b/settings.yaml");
        assert_eq!(location.dir, "/srv/proxy-b");
    }

    #[test]
    fn a_windows_path_written_with_forward_slashes_is_split_the_same() {
        let location = explicit_settings_file_of("C:/proxy/settings.yaml").unwrap();
        assert_eq!(location.dir, "C:/proxy");
    }

    #[test]
    fn a_file_in_the_root_folder_keeps_the_root() {
        assert_eq!(explicit_settings_file_of("/settings.yaml").unwrap().dir, "/");
        assert_eq!(
            explicit_settings_file_of(r"C:\settings.yaml").unwrap().dir,
            "C:"
        );
    }

    #[test]
    fn the_verbatim_prefix_of_canonicalize_is_taken_off() {
        let location = explicit_settings_file_of(r"\\?\C:\proxy\settings.yaml").unwrap();
        assert_eq!(location.file, r"C:\proxy\settings.yaml");
        assert_eq!(location.dir, r"C:\proxy");

        let location =
            explicit_settings_file_of(r"\\?\UNC\srv\share\proxy\settings.yaml").unwrap();
        assert_eq!(location.file, r"\\srv\share\proxy\settings.yaml");
        assert_eq!(location.dir, r"\\srv\share\proxy");
    }

    #[test]
    fn a_verbatim_path_which_is_neither_a_drive_nor_a_share_is_kept() {
        let path = r"\\?\Volume{b75e2c83-0000-0000-0000-602f00000000}\settings.yaml";
        assert_eq!(strip_verbatim_prefix(path), path);
    }

    #[test]
    fn a_bare_name_is_not_a_file_in_a_folder() {
        assert!(explicit_settings_file_of("settings.yaml").is_err());
    }

    #[test]
    fn a_file_which_does_not_exist_is_refused_and_names_the_path() {
        let err = set_settings_file("/no/such/folder/settings.yaml").unwrap_err();

        assert!(err.contains("does not exist"), "{err}");
        assert!(err.contains("/no/such/folder/settings.yaml"), "{err}");
        assert!(explicit_settings_file().is_none());
    }
}
