/// One titled table of the debug page, as `(name, value)` rows.
pub struct DebugPageSection {
    pub title: &'static str,
    pub rows: Vec<(String, String)>,
}

/// The diagnostic page shown to the `global_settings.debug_ip` sources.
///
/// Unlike `generate_layout`, which returns a complete raw HTTP/1.1 response
/// (status line and headers included) for the H1 server to write to the socket
/// as is, this is the HTML document alone — the caller owns the status and the
/// `content-type`.
///
/// Every value is HTML-escaped here: hosts, URIs and headers come straight
/// from the request.
pub fn generate_debug_page(
    status_code: u16,
    text: &str,
    description: &str,
    sections: &[DebugPageSection],
) -> String {
    use crate::app::APP_VERSION;

    let text = html_escape(text);
    let description = html_escape(description);

    let mut tables = String::new();
    for section in sections {
        tables.push_str("<h3>");
        tables.push_str(&html_escape(section.title));
        tables.push_str("</h3>\n<table>\n");

        if section.rows.is_empty() {
            tables.push_str("<tr><td colspan=\"2\">(none)</td></tr>\n");
        }

        for (name, value) in &section.rows {
            tables.push_str("<tr><th>");
            tables.push_str(&html_escape(name));
            tables.push_str("</th><td>");
            tables.push_str(&html_escape(value));
            tables.push_str("</td></tr>\n");
        }

        tables.push_str("</table>\n");
    }

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{status_code} {text}</title>
<style>
body {{ font-family: sans-serif; text-align: center; }}
table {{ margin: 0 auto 16px auto; border-collapse: collapse; text-align: left; }}
th, td {{ border: 1px solid #ccc; padding: 4px 10px; vertical-align: top; }}
th {{ white-space: nowrap; }}
td {{ font-family: monospace; word-break: break-all; }}
</style>
</head>
<body>
<h2>{text}</h2>
<h4>{description}</h4>
<p>{status_code}</p>
<hr/>
{tables}<hr/>
<div>MyReverseProxy {APP_VERSION}</div>
</body>
</html>
"#
    )
}

fn html_escape(src: &str) -> String {
    let mut result = String::with_capacity(src.len());
    for c in src.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#39;"),
            _ => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_sections_as_tables() {
        let page = generate_debug_page(
            400,
            "No configuration found",
            "Nothing is configured for this host",
            &[
                DebugPageSection {
                    title: "Request",
                    rows: vec![("Host".to_string(), "example.com".to_string())],
                },
                DebugPageSection {
                    title: "Hosts configured on this listener",
                    rows: vec![],
                },
            ],
        );

        assert!(page.starts_with("<!DOCTYPE html>"));
        assert!(page.contains("<h2>No configuration found</h2>"));
        assert!(page.contains("<h3>Request</h3>"));
        assert!(page.contains("<tr><th>Host</th><td>example.com</td></tr>"));
        assert!(page.contains("(none)"));
    }

    #[test]
    fn escapes_what_comes_from_the_request() {
        let page = generate_debug_page(
            400,
            "No configuration found",
            "host <script>alert(1)</script>",
            &[DebugPageSection {
                title: "Request",
                rows: vec![(
                    "x-\"quoted\"".to_string(),
                    "<img src=x onerror='a&b'>".to_string(),
                )],
            }],
        );

        assert!(!page.contains("<script>"));
        assert!(!page.contains("<img"));
        assert!(page.contains("host &lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(page.contains("x-&quot;quoted&quot;"));
        assert!(page.contains("&lt;img src=x onerror=&#39;a&amp;b&#39;&gt;"));
    }
}
