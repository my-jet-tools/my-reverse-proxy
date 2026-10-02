#[derive(Debug, Clone, Copy)]
pub enum ListenHttpEndpointType {
    Http1,
    Http2,
    Https1,
    Https2,
    Mcp,
}

impl ListenHttpEndpointType {
    pub fn can_be_under_the_same_port(&self, other: Self) -> bool {
        match self {
            Self::Http1 => match other {
                Self::Http1 => true,
                Self::Http2 | Self::Https1 | Self::Https2 | Self::Mcp => false,
            },
            Self::Http2 => match other {
                Self::Http2 => true,
                Self::Http1 | Self::Https1 | Self::Https2 | Self::Mcp => false,
            },
            Self::Https1 => match other {
                Self::Https1 | Self::Https2 | Self::Mcp => true,
                Self::Http1 | Self::Http2 => false,
            },
            Self::Https2 => match other {
                Self::Https1 | Self::Https2 => true,
                Self::Http1 | Self::Http2 | Self::Mcp => false,
            },
            Self::Mcp => match other {
                Self::Mcp | Self::Https1 | Self::Https2 => true,
                Self::Http1 | Self::Http2 => false,
            },
        }
    }

    pub fn is_http1_or_mcp(&self) -> bool {
        match self {
            Self::Http1 | Self::Https1 | Self::Mcp => true,
            Self::Http2 | Self::Https2 => false,
        }
    }

    /*
       pub fn is_http2(&self) -> bool {
           match self {
               Self::Http2 => true,
               Self::Https2 => true,
               _ => false,
           }
       }
    */
    pub fn is_https(&self) -> bool {
        match self {
            Self::Https1 | Self::Https2 => true,
            Self::Http1 | Self::Http2 | Self::Mcp => false,
        }
    }

    pub fn is_https_or_mcp(&self) -> bool {
        match self {
            Self::Https1 | Self::Https2 | Self::Mcp => true,
            Self::Http1 | Self::Http2 => false,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Http1 => "http",
            Self::Http2 => "http2",
            Self::Https1 => "https",
            Self::Https2 => "https2",
            Self::Mcp => "mcp",
        }
    }
}
