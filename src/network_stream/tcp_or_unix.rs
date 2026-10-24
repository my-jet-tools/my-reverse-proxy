pub enum TcpOrUnixSocket<TTcp, #[cfg(unix)] TUnix> {
    Tcp(TTcp),
    #[cfg(unix)]
    Unix(TUnix),
}
