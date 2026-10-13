use std::time::Duration;

use rust_extensions::SliceOrVec;

const PING: u8 = 0;
const PONG: u8 = 1;
const CONNECT_OK_PACKET_ID: u8 = 4;
const CONNECTION_ERROR_PACKET_ID: u8 = 5;
const SEND_PAYLOAD_PACKET_ID: u8 = 6;
const RECEIVE_PAYLOAD_PACKET_ID: u8 = 7;
const UPDATE_PING_TIME_PACKET_ID: u8 = 8;
const GET_FILE_REQUEST_PACKET_ID: u8 = 9;
const GET_FILE_RESPONSE_PACKET_ID: u8 = 10;
const SYNC_SSL_CERTIFICATES_PACKET_ID: u8 = 11;
const SYNC_SSL_CERTIFICATES_REQUEST_PACKET_ID: u8 = 12;
const SYNC_SSL_CERTIFICATE_NOT_FOUND_PACKET_ID: u8 = 13;
/// `CONNECT` carries the initiator's receive window. Code 3 - `CONNECT` without one, of protocol
/// version 1 - is not a frame type any more.
const CONNECT_PACKET_ID: u8 = 14;
const WINDOW_UPDATE_PACKET_ID: u8 = 15;
/// Explicit ends of a tunnelled connection.
const FIN_PACKET_ID: u8 = 16;
const RST_PACKET_ID: u8 = 17;

/// Largest frame a peer accepts - what follows a frame length on the wire. A bigger one closes
/// the gateway connection.
pub const MAX_PAYLOAD_SIZE: usize = 5 * 1024 * 1024;

/// Largest batch a peer unpacks: a packed batch which says it is bigger closes the gateway
/// connection.
pub const MAX_DECOMPRESSED_BATCH_SIZE: usize = 16 * 1024 * 1024;

/// Largest payload a sender puts into one `SEND_PAYLOAD` / `RECEIVE_PAYLOAD` frame. A bigger
/// write goes out as several frames, so one connection's bulk transfer never holds the link
/// for long between other connections' frames.
pub const MAX_PAYLOAD_CHUNK: usize = 256 * 1024;

/// Largest file a `GET_FILE_RESPONSE` carries. The response is a single inner frame, and a
/// sealed frame of its own - what is queued ahead of it goes in the frame before - so it has
/// to fit [`MAX_PAYLOAD_SIZE`] with the header of its inner frame, the kind of the batch and
/// the tag: 27 bytes of the 64 KiB left here, the rest is spare.
pub const MAX_FILE_RESPONSE_SIZE: usize = MAX_PAYLOAD_SIZE - 64 * 1024;

/// Bit set in every connection id the gateway server allocates and in none a client allocates.
/// Both ends open connections over one gateway connection, each numbering its own, and
/// `CONNECTION_ERROR` names a connection by id alone - with overlapping numbering, closing a
/// connection opened from one end would also close the one with the same id from the other.
pub const SERVER_CONNECTION_ID_FLAG: u32 = 0x8000_0000;

/// How one end of a tunnelled connection tells the other that the connection ended. Either way
/// the receiving end first delivers what arrived before.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionEnd<'s> {
    /// Closed cleanly: what was sent before is the whole stream. A proxy stream's reader gets EOF,
    /// a target gets the end of the stream.
    Closed,
    /// Broken: the stream may be cut short, for the reason given. A proxy stream's reader gets an
    /// error, a target connection is reset.
    Reset(&'s str),
}

impl<'s> ConnectionEnd<'s> {
    /// The frame which tells the peer: `FIN` for a clean close, `RST` with the reason for a
    /// reset.
    pub fn to_contract(self, connection_id: u32) -> TcpGatewayContract<'s> {
        match self {
            Self::Closed => TcpGatewayContract::Fin { connection_id },
            Self::Reset(reason) => TcpGatewayContract::Rst {
                connection_id,
                reason,
            },
        }
    }
}

#[derive(Debug)]
pub enum GetFileStatus {
    Ok,
    Error,
}

impl GetFileStatus {
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Error => 1,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Ok,
            _ => Self::Error,
        }
    }
}

#[derive(Debug)]
pub enum TcpGatewayContract<'s> {
    Connect {
        connection_id: u32,
        timeout: Duration,
        remote_host: &'s str,
        /// The initiator's receive window: the acceptor's credit for what it sends back.
        receive_window: u32,
    },
    /// The sender of this frame lets the other end send `credit` more payload bytes of
    /// `connection_id` towards it.
    WindowUpdate {
        connection_id: u32,
        credit: u32,
    },
    Connected {
        connection_id: u32,
    },
    ConnectionError {
        connection_id: u32,
        error: &'s str,
    },
    /// The sender closed `connection_id` cleanly: what it sent before is the whole stream.
    Fin {
        connection_id: u32,
    },
    /// `connection_id` broke on the sender's side: what it sent may be cut short.
    Rst {
        connection_id: u32,
        reason: &'s str,
    },
    ForwardPayload {
        connection_id: u32,
        payload: SliceOrVec<'s, u8>,
    },
    BackwardPayload {
        connection_id: u32,
        payload: SliceOrVec<'s, u8>,
    },
    /// The client's keepalive, which the server answers with `Pong`.
    Ping,
    Pong,
    UpdatePingTime {
        duration: Duration,
    },
    GetFileRequest {
        path: &'s str,
        request_id: u32,
    },
    GetFileResponse {
        request_id: u32,
        status: GetFileStatus,
        content: SliceOrVec<'s, u8>,
    },
    SyncSslCertificates {
        cert_id: &'s str,
        cert_pem: SliceOrVec<'s, u8>,
        private_key_pem: SliceOrVec<'s, u8>,
    },
    SyncSslCertificatesRequest {
        cert_ids: Vec<&'s str>,
    },
    SyncSslCertificateNotFound {
        cert_id: &'s str,
    },
}

impl<'s> TcpGatewayContract<'s> {
    /// Parse a single inner frame body: `[u8 TYPE][PAYLOAD]` - one of those a batch carries.
    /// The caller has already opened the frame and unpacked its batch.
    pub fn parse(payload: &'s [u8]) -> Result<Self, String> {
        if payload.is_empty() {
            return Err("Empty packet".to_string());
        }
        let packet_type = payload[0];
        let payload = &payload[1..];
        match packet_type {
            // Every fixed-size field is read through `read_u8` / `read_u32` / `read_u64`, which
            // turn a short frame into an error. Slicing past the fields afterwards is in bounds.
            CONNECT_PACKET_ID => {
                let connection_id = read_u32(payload, 0)?;

                // A sender never sends 0: it is taken as a second, not as a connect which fails
                // on the spot.
                let timeout = read_u8(payload, 4)?.max(1);

                let receive_window = read_u32(payload, 5)?;

                let remote_host = convert_to_string(&payload[9..], "CONNECT")?;

                Ok(Self::Connect {
                    connection_id,
                    remote_host,
                    timeout: Duration::from_secs(timeout as u64),
                    receive_window,
                })
            }
            WINDOW_UPDATE_PACKET_ID => Ok(Self::WindowUpdate {
                connection_id: read_u32(payload, 0)?,
                credit: read_u32(payload, 4)?,
            }),
            CONNECT_OK_PACKET_ID => {
                let connection_id = read_u32(payload, 0)?;

                Ok(Self::Connected { connection_id })
            }
            CONNECTION_ERROR_PACKET_ID => {
                let connection_id = read_u32(payload, 0)?;

                let error = convert_to_string(&payload[4..], "CONNECTION")?;
                Ok(Self::ConnectionError {
                    connection_id,
                    error,
                })
            }
            FIN_PACKET_ID => Ok(Self::Fin {
                connection_id: read_u32(payload, 0)?,
            }),
            RST_PACKET_ID => {
                let connection_id = read_u32(payload, 0)?;

                let reason = convert_to_string(&payload[4..], "RST")?;
                Ok(Self::Rst {
                    connection_id,
                    reason,
                })
            }

            SEND_PAYLOAD_PACKET_ID => {
                let connection_id = read_u32(payload, 0)?;

                let payload_bytes: SliceOrVec<'_, u8> = (&payload[4..]).into();

                Ok(Self::ForwardPayload {
                    connection_id,
                    payload: payload_bytes,
                })
            }

            RECEIVE_PAYLOAD_PACKET_ID => {
                let connection_id = read_u32(payload, 0)?;

                let payload_bytes: SliceOrVec<'_, u8> = (&payload[4..]).into();

                Ok(Self::BackwardPayload {
                    connection_id,
                    payload: payload_bytes,
                })
            }

            UPDATE_PING_TIME_PACKET_ID => {
                let micros = read_u64(payload, 0)?;

                let duration = Duration::from_micros(micros);

                Ok(Self::UpdatePingTime { duration })
            }

            GET_FILE_REQUEST_PACKET_ID => {
                let request_id = read_u32(payload, 0)?;

                let path = convert_to_string(&payload[4..], "GET_FILE_REQUEST")?;

                Ok(Self::GetFileRequest { path, request_id })
            }

            GET_FILE_RESPONSE_PACKET_ID => {
                let request_id = read_u32(payload, 0)?;

                let status = GetFileStatus::from_u8(read_u8(payload, 4)?);

                let content: SliceOrVec<'_, u8> = (&payload[5..]).into();

                Ok(Self::GetFileResponse {
                    request_id,
                    status,
                    content,
                })
            }

            SYNC_SSL_CERTIFICATE_NOT_FOUND_PACKET_ID => {
                let mut offset = 0usize;
                let id_len = read_u32(payload, offset)? as usize;
                offset += 4;
                let id_end = offset + id_len;
                if payload.len() < id_end {
                    return Err("SYNC_SSL_CERTIFICATE_NOT_FOUND: truncated cert_id".to_string());
                }
                let cert_id = std::str::from_utf8(&payload[offset..id_end]).map_err(|_| {
                    "SYNC_SSL_CERTIFICATE_NOT_FOUND: invalid UTF-8 in cert_id".to_string()
                })?;

                Ok(Self::SyncSslCertificateNotFound { cert_id })
            }

            SYNC_SSL_CERTIFICATES_REQUEST_PACKET_ID => {
                let mut offset = 0usize;
                let count = read_u32(payload, offset)? as usize;
                offset += 4;

                // `count` comes off the wire: every id takes at least its 4-byte length, so the
                // payload bounds how many there can really be.
                let mut cert_ids = Vec::with_capacity(count.min(payload.len() / 4));
                for _ in 0..count {
                    let id_len = read_u32(payload, offset)? as usize;
                    offset += 4;
                    let id_end = offset + id_len;
                    if payload.len() < id_end {
                        return Err("CLIENT_SSL_CERT_REQUEST: truncated cert_id".to_string());
                    }
                    let id = std::str::from_utf8(&payload[offset..id_end]).map_err(|_| {
                        "CLIENT_SSL_CERT_REQUEST: invalid UTF-8 in cert_id".to_string()
                    })?;
                    offset = id_end;
                    cert_ids.push(id);
                }

                Ok(Self::SyncSslCertificatesRequest { cert_ids })
            }

            SYNC_SSL_CERTIFICATES_PACKET_ID => {
                let mut offset = 0usize;

                let cert_id_len = read_u32(payload, offset)? as usize;
                offset += 4;
                let cert_id_end = offset + cert_id_len;
                if payload.len() < cert_id_end {
                    return Err("SERVER_SSL_CERT_PUSH: truncated cert_id".to_string());
                }
                let cert_id = std::str::from_utf8(&payload[offset..cert_id_end])
                    .map_err(|_| "SERVER_SSL_CERT_PUSH: invalid UTF-8 in cert_id".to_string())?;
                offset = cert_id_end;

                let cert_pem_len = read_u32(payload, offset)? as usize;
                offset += 4;
                let cert_pem_end = offset + cert_pem_len;
                if payload.len() < cert_pem_end {
                    return Err("SERVER_SSL_CERT_PUSH: truncated cert_pem".to_string());
                }
                let cert_pem = &payload[offset..cert_pem_end];
                offset = cert_pem_end;

                let pk_pem_len = read_u32(payload, offset)? as usize;
                offset += 4;
                let pk_pem_end = offset + pk_pem_len;
                if payload.len() < pk_pem_end {
                    return Err("SERVER_SSL_CERT_PUSH: truncated private_key_pem".to_string());
                }
                let private_key_pem = &payload[offset..pk_pem_end];

                Ok(Self::SyncSslCertificates {
                    cert_id,
                    cert_pem: SliceOrVec::AsSlice(cert_pem),
                    private_key_pem: SliceOrVec::AsSlice(private_key_pem),
                })
            }

            // Both are read by the type alone.
            PING => Ok(Self::Ping),
            PONG => Ok(Self::Pong),

            _ => Err(format!("Unknown packet type: {}", packet_type)),
        }
    }

    /// Serialize the contract into its plaintext inner-frame form:
    /// `[u32 LEN][u8 TYPE][PAYLOAD]`. The writer task puts the inner frames
    /// queued by a flush into a batch, or two, and seals each as a frame.
    pub fn to_plain_frame(&self) -> Vec<u8> {
        let mut body = Vec::new();

        match self {
            Self::Connect {
                connection_id,
                timeout,
                remote_host,
                receive_window,
            } => {
                body.push(CONNECT_PACKET_ID);
                push_u32(&mut body, *connection_id);
                body.push(connect_timeout_to_wire(*timeout));
                push_u32(&mut body, *receive_window);
                body.extend_from_slice(remote_host.as_bytes());
            }
            Self::WindowUpdate {
                connection_id,
                credit,
            } => {
                body.push(WINDOW_UPDATE_PACKET_ID);
                push_u32(&mut body, *connection_id);
                push_u32(&mut body, *credit);
            }

            Self::Connected { connection_id } => {
                body.push(CONNECT_OK_PACKET_ID);
                push_u32(&mut body, *connection_id);
            }
            Self::ConnectionError {
                connection_id,
                error,
            } => {
                body.push(CONNECTION_ERROR_PACKET_ID);
                push_u32(&mut body, *connection_id);
                body.extend_from_slice(error.as_bytes());
            }
            Self::Fin { connection_id } => {
                body.push(FIN_PACKET_ID);
                push_u32(&mut body, *connection_id);
            }
            Self::Rst {
                connection_id,
                reason,
            } => {
                body.push(RST_PACKET_ID);
                push_u32(&mut body, *connection_id);
                body.extend_from_slice(reason.as_bytes());
            }

            Self::ForwardPayload {
                connection_id,
                payload,
            } => {
                body.push(SEND_PAYLOAD_PACKET_ID);
                push_u32(&mut body, *connection_id);
                body.extend_from_slice(payload.as_slice());
            }
            Self::BackwardPayload {
                connection_id,
                payload,
            } => {
                body.push(RECEIVE_PAYLOAD_PACKET_ID);
                push_u32(&mut body, *connection_id);
                body.extend_from_slice(payload.as_slice());
            }

            Self::UpdatePingTime { duration } => {
                let micros = duration.as_micros() as u64;
                body.push(UPDATE_PING_TIME_PACKET_ID);
                body.extend_from_slice(&micros.to_le_bytes());
            }
            Self::GetFileRequest { path, request_id } => {
                body.push(GET_FILE_REQUEST_PACKET_ID);
                body.extend_from_slice(request_id.to_le_bytes().as_slice());
                body.extend_from_slice(path.as_bytes());
            }
            Self::GetFileResponse {
                request_id,
                status,
                content,
            } => {
                body.push(GET_FILE_RESPONSE_PACKET_ID);
                body.extend_from_slice(request_id.to_le_bytes().as_slice());
                body.push(status.as_u8());
                body.extend_from_slice(content.as_slice());
            }
            Self::SyncSslCertificates {
                cert_id,
                cert_pem,
                private_key_pem,
            } => {
                body.push(SYNC_SSL_CERTIFICATES_PACKET_ID);

                let id_bytes = cert_id.as_bytes();
                push_u32(&mut body, id_bytes.len() as u32);
                body.extend_from_slice(id_bytes);

                let cp = cert_pem.as_slice();
                push_u32(&mut body, cp.len() as u32);
                body.extend_from_slice(cp);

                let pk = private_key_pem.as_slice();
                push_u32(&mut body, pk.len() as u32);
                body.extend_from_slice(pk);
            }
            Self::SyncSslCertificatesRequest { cert_ids } => {
                body.push(SYNC_SSL_CERTIFICATES_REQUEST_PACKET_ID);
                push_u32(&mut body, cert_ids.len() as u32);
                for id in cert_ids {
                    let bytes = id.as_bytes();
                    push_u32(&mut body, bytes.len() as u32);
                    body.extend_from_slice(bytes);
                }
            }
            Self::SyncSslCertificateNotFound { cert_id } => {
                body.push(SYNC_SSL_CERTIFICATE_NOT_FOUND_PACKET_ID);
                let bytes = cert_id.as_bytes();
                push_u32(&mut body, bytes.len() as u32);
                body.extend_from_slice(bytes);
            }
            Self::Ping => {
                body.push(PING);
            }
            Self::Pong => {
                body.push(PONG);
            }
        }

        let len = body.len();
        let mut result = Vec::with_capacity(4 + len);
        result.extend_from_slice(&(len as u32).to_le_bytes());
        result.extend_from_slice(&body);
        result
    }
}

fn push_u32(result: &mut Vec<u8>, value: u32) {
    result.extend_from_slice(value.to_le_bytes().as_slice());
}

/// The connect timeout travels as whole seconds in one byte. A sub-second remainder is rounded
/// up - a 500ms timeout must not become 0, an instant failure on the peer - and the value is
/// clamped to what the byte holds.
fn connect_timeout_to_wire(timeout: Duration) -> u8 {
    let mut secs = timeout.as_secs();
    if timeout.subsec_nanos() > 0 {
        secs += 1;
    }
    secs.clamp(1, u8::MAX as u64) as u8
}

fn read_u8(payload: &[u8], offset: usize) -> Result<u8, String> {
    payload
        .get(offset)
        .copied()
        .ok_or_else(|| "truncated u8".to_string())
}

fn read_u32(payload: &[u8], offset: usize) -> Result<u32, String> {
    if payload.len() < offset + 4 {
        return Err("truncated u32".to_string());
    }
    Ok(u32::from_le_bytes([
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
    ]))
}

fn read_u64(payload: &[u8], offset: usize) -> Result<u64, String> {
    let Some(bytes) = payload.get(offset..offset + 8) else {
        return Err("truncated u64".to_string());
    };
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn convert_to_string<'s>(payload: &'s [u8], packet_type: &str) -> Result<&'s str, String> {
    if payload.is_empty() {
        return Ok("");
    }

    std::str::from_utf8(payload)
        .map_err(|_| format!("Can not convert path to string during parsing [{packet_type}]."))
}
