//! Local Unix system-bus transport. Secret bytes travel only through sealed FDs.
use crate::{ManagementRequest, ManagementResponse};
use color_eyre::{
    Result,
    eyre::{bail, eyre},
};
use std::{
    fs::File,
    io::{Cursor, Write},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::FileExt,
    },
    time::Duration,
};
use zbus::{Connection, zvariant::OwnedFd};
use zeroize::Zeroizing;

pub const MAX_REQUEST_BYTES: usize = 16 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub fn seal_request(request: &ManagementRequest) -> Result<OwnedFd> {
    // Fixed-size backing storage cannot reallocate and abandon secret bytes.
    let mut bytes = Zeroizing::new(vec![0u8; MAX_REQUEST_BYTES]);
    let mut encoded = Cursor::new(&mut bytes[..]);
    ciborium::into_writer(request, &mut encoded)
        .map_err(|_| eyre!("management request too large"))?;
    let length = encoded.position() as usize;
    // SAFETY: constant NUL-terminated name; ownership is immediately adopted.
    let raw = unsafe {
        libc::memfd_create(
            c"tpm-passkey-request".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(raw) };
    file.write_all(&bytes[..length])?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(std::os::fd::OwnedFd::from(file).into())
}

pub fn read_request(fd: &OwnedFd) -> Result<ManagementRequest> {
    let file = File::from(fd.as_fd().try_clone_to_owned()?);
    // Check irreversible seals BEFORE size, so a racing sender cannot grow
    // the file and seal a different length after our metadata snapshot.
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
    if seals < 0 || seals & required != required {
        bail!("management descriptor must be sealed");
    }
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_REQUEST_BYTES as u64 {
        bail!("invalid management descriptor type or size");
    }
    let mut bytes = Zeroizing::new(vec![0; metadata.len() as usize]);
    file.read_exact_at(&mut bytes, 0)?;
    let mut cursor = Cursor::new(&bytes[..]);
    // Never echo decoding errors containing secret input.
    let mut scratch = Zeroizing::new([0u8; MAX_REQUEST_BYTES]);
    let request = ciborium::de::from_reader_with_buffer(&mut cursor, &mut *scratch)
        .map_err(|_| eyre!("invalid management request"))?;
    if cursor.position() != bytes.len() as u64 {
        bail!("trailing management request data");
    }
    Ok(request)
}

pub async fn connect_system_bus() -> zbus::Result<Connection> {
    use std::os::{linux::net::SocketAddrExt, unix::net::SocketAddr};
    use zbus::address::transport::{Transport, UnixSocket};
    let address = zbus::Address::system()?;
    let Transport::Unix(unix) = address.transport() else {
        return Err(zbus::Error::Unsupported);
    };
    let socket_address = match unix.path() {
        UnixSocket::File(path) => SocketAddr::from_pathname(path)?,
        UnixSocket::Abstract(name) => SocketAddr::from_abstract_name(name.as_encoded_bytes())?,
        _ => return Err(zbus::Error::Unsupported),
    };
    let stream = tokio::net::UnixStream::connect_addr(&socket_address.into()).await?;
    let connection = zbus::connection::Builder::unix_stream(stream)
        .build()
        .await?;
    if let Some(guid) = address.guid()
        && connection.server_guid().as_str() != guid.as_str()
    {
        return Err(zbus::Error::Handshake("system bus GUID mismatch".into()));
    }
    Ok(connection)
}

pub fn send_request(request: &ManagementRequest) -> Result<ManagementResponse> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(120), async {
            let connection = connect_system_bus().await?;
            let proxy = zbus::fdo::DBusProxy::new(&connection).await?;
            let owner = proxy.get_name_owner(crate::BUS_NAME.try_into()?).await?;
            if proxy
                .get_connection_unix_user(owner.as_str().try_into()?)
                .await?
                != 0
            {
                bail!("management service is not owned by root");
            }
            let fd = seal_request(request)?;
            let reply = connection
                .call_method(
                    Some(owner.as_str()),
                    crate::DAEMON_PATH,
                    Some(crate::DAEMON_IFACE),
                    "Manage",
                    &(request.operation(), fd),
                )
                .await?;
            let bytes: Vec<u8> = reply.body().deserialize()?;
            if bytes.len() > MAX_RESPONSE_BYTES {
                bail!("management response too large");
            }
            ciborium::from_reader(&bytes[..]).map_err(|_| eyre!("invalid management response"))
        })
        .await
        .map_err(|_| eyre!("management request timed out"))?
    })
}
