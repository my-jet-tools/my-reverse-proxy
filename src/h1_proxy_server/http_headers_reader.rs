use crate::h1_utils::*;

#[derive(Clone, Copy)]
pub struct HttpHeadersReader<'s> {
    pub http_headers: &'s Http1Headers,
    pub payload: &'s [u8],
}

impl<'l> crate::types::HttpRequestReader for HttpHeadersReader<'l> {
    fn get_cookie<'s>(&'s self, cookie_name: &str) -> Option<&'s str> {
        let cookie = self.http_headers.cookie_value.as_ref()?;

        // The bytes are off the wire: a value which is not UTF-8 is no cookie.
        let cookie_string = std::str::from_utf8(&self.payload[cookie.start..cookie.end]).ok()?;

        crate::utils::get_cookie(cookie_string, cookie_name)
    }

    fn get_query_string(&self) -> Option<&str> {
        let path_and_query = self.get_path_and_query()?;

        path_and_query
            .find('?')
            .map(|index| &path_and_query[index + 1..])
    }

    fn get_host(&self) -> Option<&str> {
        let host_value = self.http_headers.host_value.as_ref()?;

        std::str::from_utf8(&self.payload[host_value.start..host_value.end]).ok()
    }

    /// `None`: the first line is not a request line.
    fn get_path_and_query(&self) -> Option<&str> {
        let first_line = self.http_headers.get_first_line(self.payload);

        split_request_line(first_line.data).map(|(_method, target)| target)
    }

    fn get_path(&self) -> &str {
        let Some(path_and_query) = self.get_path_and_query() else {
            return "/";
        };

        match path_and_query.find("?") {
            Some(index) => &path_and_query[..index],
            None => path_and_query,
        }
    }
}
