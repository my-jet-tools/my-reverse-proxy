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

/// The content of the remote file `path` - or `None` when what is there is not a file: a
/// directory, a device, a socket.
///
/// An ssh host opens a directory for reading as readily as a file, and fails on the first read
/// of it with a bare `Failure`. Asked what it has opened, it says so - and a path which is not
/// a file is told apart from a host which could not be read.
pub async fn download_remote_regular_file(
    ssh_session: &SshSession,
    path: &str,
    timeout: Duration,
) -> Result<Option<Vec<u8>>, SshSessionError> {
    let mut file = ssh_session
        .open_remote_file(path, OpenFlags::READ, None, timeout)
        .await?;

    let Ok(metadata) = tokio::time::timeout(timeout, file.metadata()).await else {
        return Err(SshSessionError::Timeout);
    };

    if !metadata?.is_regular() {
        return Ok(None);
    }

    let mut content = Vec::new();

    let Ok(result) = tokio::time::timeout(timeout, file.read_to_end(&mut content)).await else {
        return Err(SshSessionError::Timeout);
    };

    result?;

    Ok(Some(content))
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

/// True if the remote side would not take the name at all. An OpenSSH server answers a path
/// longer than its file system takes (`ENAMETOOLONG`) with `Bad message`, not with `No such
/// file` - and there is no file under such a name.
pub fn is_remote_name_refused(err: &SshSessionError) -> bool {
    use my_ssh::russh_sftp::{client::error::Error, protocol::StatusCode};

    match err {
        SshSessionError::SftpError(Error::Status(status)) => {
            status.status_code == StatusCode::BadMessage
        }
        _ => false,
    }
}
