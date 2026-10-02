use std::time::Duration;

use my_ssh::{russh_sftp::protocol::OpenFlags, SshSession, SshSessionError};
use tokio::io::AsyncReadExt;

/// Reads the whole remote file over SFTP. The timeout covers opening the file and,
/// separately, reading its content.
pub async fn download_remote_file(
    ssh_session: &SshSession,
    path: &str,
    timeout: Duration,
) -> Result<Vec<u8>, SshSessionError> {
    let mut file = ssh_session
        .open_remote_file(path, OpenFlags::READ, None, timeout)
        .await?;

    let mut content = Vec::new();

    let Ok(result) = tokio::time::timeout(timeout, file.read_to_end(&mut content)).await else {
        return Err(SshSessionError::Timeout);
    };

    result?;

    Ok(content)
}

/// True if the remote side answered that the file does not exist.
pub fn is_remote_file_not_found(err: &SshSessionError) -> bool {
    use my_ssh::russh_sftp::{client::error::Error, protocol::StatusCode};

    match err {
        SshSessionError::SftpError(Error::Status(status)) => {
            status.status_code == StatusCode::NoSuchFile
        }
        _ => false,
    }
}
