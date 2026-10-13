use std::path::PathBuf;

pub const INDEX_HTML: &[u8] = b"<h1>index</h1>";
pub const SITE_CSS: &[u8] = b"body { margin: 0 }";
/// What a files location must never serve: it is beside the folder, not in it.
pub const SECRET: &[u8] = b"the secret beside the folder";

/// A folder for a files location to serve - `root`, with `index.html` and `css/site.css` in it -
/// and `secret.txt` beside it. A directory of its own for each test, removed when the test ends.
pub struct TestSite {
    dir: PathBuf,
}

impl TestSite {
    pub fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("mrp-files-{}", uuid::Uuid::new_v4().simple()));

        std::fs::create_dir_all(dir.join("root").join("css")).unwrap();
        std::fs::write(dir.join("root").join("index.html"), INDEX_HTML).unwrap();
        std::fs::write(dir.join("root").join("css").join("site.css"), SITE_CSS).unwrap();
        std::fs::write(dir.join("secret.txt"), SECRET).unwrap();

        Self { dir }
    }

    /// The folder the location serves.
    pub fn root(&self) -> String {
        self.dir.join("root").to_str().unwrap().to_string()
    }
}

impl Drop for TestSite {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
