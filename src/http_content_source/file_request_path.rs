use std::borrow::Cow;

/// The path of a request to a files location which passed the check: it can be glued to the
/// folder. [`FileRequestPath::parse`] is the only way to get one, and the sources of a files
/// location take nothing else - a caller can not skip the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRequestPath<'s> {
    /// As received - not decoded. Starts with `/`.
    path: &'s str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadFileRequestPath {
    /// Not an origin-form path: it does not start with `/`.
    NotAbsolute,
    /// A `..` segment - written as it is or percent-encoded.
    ParentSegment,
    /// NUL or another control character - written as it is or percent-encoded.
    ControlCharacter,
    /// An empty segment which is not the last one, or a `.` segment: `//x` and `/./x` are the
    /// file `/x` written another way.
    AliasSegment,
}

impl<'s> FileRequestPath<'s> {
    /// `path`: the request path as received - not decoded, without the query string.
    ///
    /// The path is decoded for the check only, and once. Nothing behind the check decodes it:
    /// the file is looked up by the name as it was received.
    pub fn parse(path: &'s str) -> Result<Self, BadFileRequestPath> {
        let path = if path.is_empty() { "/" } else { path };

        // `*`, `http://host/x`, `host:443`, a relative path. Glued to the folder `/srv/www`,
        // the path `-backup/x` would be a file of the folder next to it.
        if !path.starts_with('/') {
            return Err(BadFileRequestPath::NotAbsolute);
        }

        let decoded = percent_decode(path.as_bytes());

        // NUL cuts a path short in the C strings behind SFTP; the other control characters
        // would get into the logs as they are.
        if decoded.iter().any(|b| *b < 0x20 || *b == 0x7F) {
            return Err(BadFileRequestPath::ControlCharacter);
        }

        // A backslash separates nothing on unix; taking it for a separator here costs nothing.
        if decoded
            .split(|b| *b == b'/' || *b == b'\\')
            .any(|segment| segment == b"..")
        {
            return Err(BadFileRequestPath::ParentSegment);
        }

        // To the file system `//x` and `/./x` are the file `/x`; to the rules they are another
        // path: the location of a request is picked by the path as it is written, so such a
        // spelling would be served past a location written for `/x` - its `drop`, its
        // `auth_header`. A path names its file in one way only. The last segment may be empty:
        // `/css/`.
        let mut segments = path[1..].split('/').peekable();
        while let Some(segment) = segments.next() {
            let is_last = segments.peek().is_none();

            if segment == "." || (segment.is_empty() && !is_last) {
                return Err(BadFileRequestPath::AliasSegment);
            }
        }

        Ok(Self { path })
    }

    pub fn is_root(&self) -> bool {
        self.path == "/"
    }

    pub fn as_str(&self) -> &'s str {
        self.path
    }

    /// The file this request means inside `files_path`. `None`: the root is asked for and the
    /// location has no default file, or there is no folder.
    ///
    /// The only place where a request path is glued to a folder. The folder always goes in
    /// front: `Path::join` would start over from the root on a path which begins with `/`.
    pub fn in_folder(&self, files_path: &str, default_file: Option<&str>) -> Option<String> {
        // An empty folder would make the request path an absolute one.
        if files_path.is_empty() {
            return None;
        }

        let file = if self.is_root() {
            default_file?
        } else {
            self.path
        };

        let mut result = String::with_capacity(files_path.len() + file.len() + 1);
        result.push_str(files_path);

        if !result.ends_with('/') {
            result.push('/');
        }

        result.push_str(file.strip_prefix('/').unwrap_or(file));

        Some(result)
    }
}

/// One pass: `%XX` with two hex digits becomes the byte, anything else stays as it is - no `+`
/// for a space, no second pass. `url_utils::decode_from_url_string` is not used on purpose: on
/// an escape it can not read it gives the whole string back as it was, so one `%zz` would hide
/// a `%2e%2e` next to it.
fn percent_decode(src: &[u8]) -> Cow<'_, [u8]> {
    if !src.contains(&b'%') {
        return Cow::Borrowed(src);
    }

    let mut result = Vec::with_capacity(src.len());
    let mut i = 0;

    while i < src.len() {
        if src[i] == b'%' && i + 2 < src.len() {
            if let (Some(high), Some(low)) = (hex_digit(src[i + 1]), hex_digit(src[i + 2])) {
                result.push(high << 4 | low);
                i += 3;
                continue;
            }
        }

        result.push(src[i]);
        i += 1;
    }

    Cow::Owned(result)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(path: &str) {
        let parsed = FileRequestPath::parse(path)
            .unwrap_or_else(|err| panic!("'{}' is refused: {:?}", path.escape_debug(), err));

        if !path.is_empty() {
            assert_eq!(parsed.as_str(), path, "the path is kept as it was received");
        }
    }

    fn refused(path: &str, reason: BadFileRequestPath) {
        assert_eq!(
            FileRequestPath::parse(path),
            Err(reason),
            "'{}'",
            path.escape_debug()
        );
    }

    #[test]
    fn ordinary_paths_pass() {
        for path in [
            "",
            "/",
            "/index.html",
            "/a/b/c.css",
            "/a/",
            "/a/b/",
            "/.a",
            "/a./b",
            "/%2e/a",
            "/a/%2e",
            "/.well-known/acme-challenge/x",
            "/.env",
            "/a..b",
            "/..a",
            "/a..",
            "/a../b",
            "/...",
            "/.../x",
            "/%2e",
            "/a%2eb",
            "/file%20name.txt",
            "/100%.txt",
            "/a%2",
            "/a%",
            "/%zz",
            "/a%zz",
            "/a%2fb",
            "/a\\b",
            "/файл.txt",
            "/%D1%84.txt",
            "/%ff%fe",
            "/%c0%ae%c0%ae/x",
            "/%u002e%u002e/x",
            "/..;/x",
        ] {
            ok(path);
        }
    }

    #[test]
    fn a_parent_segment_is_refused_however_it_is_written() {
        for path in [
            "/..",
            "/../",
            "/../secret.txt",
            "/a/../b",
            "/a/..",
            "/a/../",
            "/a/b/../../../secret.txt",
            "/%2e%2e/secret.txt",
            "/%2E%2E/secret.txt",
            "/%2e%2E/secret.txt",
            "/%2E%2e/secret.txt",
            "/%2e./secret.txt",
            "/.%2e/secret.txt",
            "/.%2E/secret.txt",
            "/a/%2e%2e",
            "/..%2fsecret.txt",
            "/..%2Fsecret.txt",
            "/a%2f..%2fb",
            "/a%2F..%2Fb",
            "/a%2F%2e%2e%2Fb",
            "/%2f..",
            "/..\\secret.txt",
            "/a\\..\\b",
            "/..%5csecret.txt",
            "/..%5Csecret.txt",
            "/%2e%2e%5csecret.txt",
            "/a/%2e%2e%2f%2e%2e/x",
            // A `%` which starts no escape does not hide the escape next to it.
            "/%zz/%2e%2e/secret.txt",
        ] {
            refused(path, BadFileRequestPath::ParentSegment);
        }
    }

    /// A segment which changes nothing would let one file be asked for by several paths, and
    /// only one of them is the path the rules of a location are written for.
    #[test]
    fn a_segment_which_changes_nothing_is_refused() {
        for path in [
            "//",
            "/.",
            "/./",
            "//a",
            "///a",
            "/./a",
            "/.//a",
            "/a//b",
            "/a/./b",
            "/a//",
            "/a/.",
            "/a/./",
            "//private/report.html",
            "/./.env",
        ] {
            refused(path, BadFileRequestPath::AliasSegment);
        }
    }

    #[test]
    fn a_path_which_is_not_origin_form_is_refused() {
        for path in [
            "index.html",
            "*",
            "http://host/index.html",
            "../x",
            "..",
            "host:443",
            "-backup/x",
        ] {
            refused(path, BadFileRequestPath::NotAbsolute);
        }
    }

    #[test]
    fn control_characters_are_refused() {
        for path in [
            "/a%00.html",
            "/a\0.html",
            "/a%0d%0ab",
            "/a%0Ab",
            "/\x1b[31m",
            "/a%1b",
            "/a%7f",
            "/a%7F",
            "/a\x7f",
            "/a%09b",
        ] {
            refused(path, BadFileRequestPath::ControlCharacter);
        }
    }

    /// Nothing behind the check decodes a path, so what is encoded twice stays a name.
    #[test]
    fn a_path_is_decoded_once() {
        ok("/%252e%252e/secret.txt");
        ok("/%252e%252e%252fsecret.txt");
        ok("/%%2e%2e/x");
    }

    #[test]
    fn the_root() {
        assert!(FileRequestPath::parse("/").unwrap().is_root());
        assert!(FileRequestPath::parse("").unwrap().is_root());
        assert!(!FileRequestPath::parse("/index.html").unwrap().is_root());

        // The root has one spelling.
        assert!(FileRequestPath::parse("//").is_err());
        assert!(FileRequestPath::parse("/.").is_err());
    }

    #[test]
    fn joining_to_the_folder() {
        let path = FileRequestPath::parse("/css/site.css").unwrap();
        assert_eq!(
            path.in_folder("/srv/www", None).unwrap(),
            "/srv/www/css/site.css"
        );
        assert_eq!(
            path.in_folder("/srv/www/", None).unwrap(),
            "/srv/www/css/site.css"
        );
        assert_eq!(path.in_folder("~/www", None).unwrap(), "~/www/css/site.css");
        assert_eq!(path.in_folder("/", None).unwrap(), "/css/site.css");

        // The default file is for the root only.
        assert_eq!(
            path.in_folder("/srv/www", Some("index.html")).unwrap(),
            "/srv/www/css/site.css"
        );

        let root = FileRequestPath::parse("/").unwrap();
        assert_eq!(
            root.in_folder("/srv/www", Some("index.html")).unwrap(),
            "/srv/www/index.html"
        );
        assert_eq!(
            root.in_folder("/srv/www/", Some("/index.html")).unwrap(),
            "/srv/www/index.html"
        );
        assert_eq!(root.in_folder("/srv/www", None), None);

        // The path is glued as it was received: nothing is decoded on the way to the file.
        let path = FileRequestPath::parse("/file%20name.txt").unwrap();
        assert_eq!(
            path.in_folder("/srv/www", None).unwrap(),
            "/srv/www/file%20name.txt"
        );
    }

    /// A folder which is not there is no folder - not the root of the file system.
    #[test]
    fn an_empty_folder_has_no_files() {
        let path = FileRequestPath::parse("/etc/passwd").unwrap();
        assert_eq!(path.in_folder("", None), None);

        let root = FileRequestPath::parse("/").unwrap();
        assert_eq!(root.in_folder("", Some("index.html")), None);
    }

    /// A path can not get out of the folder by starting over from the root, the way it does
    /// with a path join.
    #[test]
    #[allow(clippy::join_absolute_paths)]
    fn a_path_which_starts_over_from_the_root_stays_in_the_folder() {
        let path = FileRequestPath::parse("/etc/passwd").unwrap();
        assert_eq!(
            path.in_folder("/srv/www", None).unwrap(),
            "/srv/www/etc/passwd"
        );

        // What the lint is there for: the join drops the folder.
        assert_eq!(
            std::path::Path::new("/srv/www")
                .join("/etc/passwd")
                .to_str()
                .unwrap(),
            "/etc/passwd"
        );
    }

    /// What the file system does with the paths the glue used to build: why `..` is refused,
    /// and why `.` and an empty segment are - to it they are the same file under another path.
    #[test]
    fn the_os_follows_a_parent_segment_and_reads_an_encoded_one_as_a_name() {
        let dir = std::env::temp_dir().join(format!(
            "files-request-path-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let root = dir.join("root");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(dir.join("secret.txt"), b"secret").unwrap();
        std::fs::write(root.join("index.html"), b"index").unwrap();

        let root = root.to_str().unwrap();

        assert_eq!(
            std::fs::read(format!("{root}/../secret.txt")).unwrap(),
            b"secret"
        );
        assert!(std::fs::read(format!("{root}/%2e%2e/secret.txt")).is_err());
        assert!(std::fs::read(format!("{root}/a\0b")).is_err());
        assert_eq!(
            std::fs::read(format!("{root}//index.html")).unwrap(),
            b"index"
        );
        assert_eq!(
            std::fs::read(format!("{root}/./index.html")).unwrap(),
            b"index"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
