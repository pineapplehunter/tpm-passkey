use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use crate::{ctap2, hid::REPORT_SIZE, store};

pub const BROADCAST_CID: u32 = 0xffff_ffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CtapHidCommand {
    Ping = 0x01,
    Init = 0x06,
    Wink = 0x08,
    Cbor = 0x10,
    Cancel = 0x11,
    Keepalive = 0x3b,
    Error = 0x3f,
}

impl CtapHidCommand {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Ping),
            0x06 => Some(Self::Init),
            0x08 => Some(Self::Wink),
            0x10 => Some(Self::Cbor),
            0x11 => Some(Self::Cancel),
            0x3b => Some(Self::Keepalive),
            0x3f => Some(Self::Error),
            _ => None,
        }
    }

    fn byte(self) -> u8 {
        self as u8
    }
}

const TYPE_INIT: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum CtapHidError {
    Command = 0x01,
    Length = 0x03,
    Seq = 0x04,
    Timeout = 0x05,
    Busy = 0x06,
    Channel = 0x0b,
    Other = 0x7f,
}

const CAPABILITY_WINK: u8 = 0x01;
const CAPABILITY_CBOR: u8 = 0x04;
const CAPABILITY_NMSG: u8 = 0x08;

const MAX_PAYLOAD_SIZE: usize = (REPORT_SIZE - 7) + 128 * (REPORT_SIZE - 5);
const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(3);
const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(100);
const KEEPALIVE_PROCESSING: u8 = 1;

pub struct PacketHandler {
    pending: Option<PendingRequest>,
    processing: Option<ProcessingRequest>,
    allocated_channels: HashSet<u32>,
    next_cid: u32,
    next_transaction_id: u64,
    worker_tx: mpsc::Sender<WorkerCommand>,
    worker_rx: mpsc::Receiver<WorkerResult>,
}

impl Default for PacketHandler {
    fn default() -> Self {
        Self::new(store::dev_store_dir(), None)
    }
}

#[derive(Debug)]
struct PendingRequest {
    cid: u32,
    command: CtapHidCommand,
    expected_len: usize,
    payload: Vec<u8>,
    next_sequence: u8,
    started_at: Instant,
}

struct ProcessingRequest {
    id: u64,
    cid: u32,
    cancelled: Arc<AtomicBool>,
    status: Arc<AtomicU8>,
    last_keepalive: Instant,
}

enum WorkerCommand {
    Cbor {
        id: u64,
        cid: u32,
        payload: Vec<u8>,
        cancelled: Arc<AtomicBool>,
        status: Arc<AtomicU8>,
    },
    CancelState,
    Tpm {
        command: crate::ctap2::TpmCommand,
        response: mpsc::Sender<crate::ctap2::TpmCmdResult>,
    },
}

struct WorkerResult {
    id: u64,
    cid: u32,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketOutcome {
    NeedMore,
    Processing,
    Ignored,
    Response(Response),
}

impl PacketHandler {
    pub fn new(store_dir: PathBuf, tpm_path: Option<PathBuf>) -> Self {
        Self::new_with_user_approval(
            store_dir,
            tpm_path,
            Box::new(crate::approval::SystemApproval),
        )
    }

    pub fn new_with_user_approval(
        store_dir: PathBuf,
        tpm_path: Option<PathBuf>,
        approval: Box<dyn crate::approval::UserApproval>,
    ) -> Self {
        let (worker_tx, command_rx) = mpsc::channel();
        let (result_tx, worker_rx) = mpsc::channel();
        thread::spawn(move || {
            let mut authenticator =
                ctap2::Authenticator::new_with_approval(store_dir, tpm_path, approval);
            while let Ok(command) = command_rx.recv() {
                match command {
                    WorkerCommand::Cbor {
                        id,
                        cid,
                        payload,
                        cancelled,
                        status,
                    } => {
                        let payload =
                            authenticator.handle_cbor_controlled(&payload, cancelled, status);
                        if result_tx.send(WorkerResult { id, cid, payload }).is_err() {
                            break;
                        }
                    }
                    WorkerCommand::CancelState => authenticator.cancel_pending(),
                    WorkerCommand::Tpm { command, response } => {
                        let result = authenticator
                            .handle_tpm_command(command)
                            .map_err(|error| format!("{error}"));
                        let _ = response.send(result);
                    }
                }
            }
        });

        Self {
            pending: None,
            processing: None,
            allocated_channels: HashSet::new(),
            next_cid: 1,
            next_transaction_id: 1,
            worker_tx,
            worker_rx,
        }
    }

    pub fn queue_tpm_command(
        &self,
        command: crate::ctap2::TpmCommand,
        response: mpsc::Sender<crate::ctap2::TpmCmdResult>,
    ) {
        if self
            .worker_tx
            .send(WorkerCommand::Tpm { command, response })
            .is_err()
        {
            log::error!("authenticator worker stopped before TPM command was queued");
        }
    }

    pub fn handle_packet(&mut self, report: &[u8]) -> Option<PacketOutcome> {
        if report.len() != REPORT_SIZE {
            return None;
        }

        let cid = u32::from_be_bytes(report[0..4].try_into().expect("fixed cid slice"));
        let packet_type = report[4];

        if packet_type & TYPE_INIT != 0 {
            self.handle_init_packet(cid, packet_type & !TYPE_INIT, report)
        } else {
            self.handle_continuation_packet(cid, packet_type, report)
        }
    }

    fn handle_init_packet(
        &mut self,
        cid: u32,
        command_id: u8,
        report: &[u8],
    ) -> Option<PacketOutcome> {
        let payload_len = u16::from_be_bytes([report[5], report[6]]) as usize;
        let Some(command) = CtapHidCommand::from_byte(command_id) else {
            return Some(PacketOutcome::Response(error(cid, CtapHidError::Command)));
        };
        if command == CtapHidCommand::Cancel {
            if !self.allocated_channels.contains(&cid) {
                return Some(PacketOutcome::Ignored);
            }
            return Some(self.cancel(cid, payload_len));
        }
        let channel_is_valid = match command {
            CtapHidCommand::Init => cid == BROADCAST_CID || self.allocated_channels.contains(&cid),
            _ => cid != BROADCAST_CID && self.allocated_channels.contains(&cid),
        };
        if cid == 0 || !channel_is_valid {
            return Some(PacketOutcome::Response(error(cid, CtapHidError::Channel)));
        }
        if payload_len > MAX_PAYLOAD_SIZE {
            self.abort_incomplete(cid);
            return Some(PacketOutcome::Response(error(cid, CtapHidError::Length)));
        }

        if command == CtapHidCommand::Init && self.active_cid() == Some(cid) {
            self.abort_transaction();
        } else if self.active_cid().is_some() {
            return Some(PacketOutcome::Response(error(cid, CtapHidError::Busy)));
        }

        let first_len = payload_len.min(REPORT_SIZE - 7);
        let mut payload = Vec::with_capacity(payload_len);
        payload.extend_from_slice(&report[7..7 + first_len]);

        if payload.len() == payload_len {
            return Some(self.dispatch(cid, command, &payload));
        }

        self.pending = Some(PendingRequest {
            cid,
            command,
            expected_len: payload_len,
            payload,
            next_sequence: 0,
            started_at: Instant::now(),
        });
        Some(PacketOutcome::NeedMore)
    }

    fn handle_continuation_packet(
        &mut self,
        cid: u32,
        sequence: u8,
        report: &[u8],
    ) -> Option<PacketOutcome> {
        if !self.allocated_channels.contains(&cid) {
            return Some(PacketOutcome::Response(error(cid, CtapHidError::Channel)));
        }
        let Some(pending) = self.pending.as_mut() else {
            return Some(PacketOutcome::Ignored);
        };
        if pending.cid != cid {
            return Some(PacketOutcome::Ignored);
        }
        if pending.next_sequence != sequence {
            self.pending = None;
            return Some(PacketOutcome::Response(error(cid, CtapHidError::Seq)));
        }

        let remaining = pending.expected_len - pending.payload.len();
        let chunk_len = remaining.min(REPORT_SIZE - 5);
        pending.payload.extend_from_slice(&report[5..5 + chunk_len]);

        if pending.payload.len() == pending.expected_len {
            let pending = self.pending.take().expect("pending request");
            Some(self.dispatch(pending.cid, pending.command, &pending.payload))
        } else {
            pending.next_sequence += 1;
            Some(PacketOutcome::NeedMore)
        }
    }

    fn dispatch(&mut self, cid: u32, command: CtapHidCommand, payload: &[u8]) -> PacketOutcome {
        log::debug!(
            "ctaphid request cid={cid:#010x} command={} payload_len={}",
            command_name(command),
            payload.len()
        );
        let response = match command {
            CtapHidCommand::Init => {
                let allocated_cid = if cid == BROADCAST_CID {
                    while self.next_cid == 0
                        || self.next_cid == BROADCAST_CID
                        || self.allocated_channels.contains(&self.next_cid)
                    {
                        self.next_cid = self.next_cid.wrapping_add(1).max(1);
                    }
                    let allocated = self.next_cid;
                    self.next_cid = self.next_cid.wrapping_add(1).max(1);
                    self.allocated_channels.insert(allocated);
                    allocated
                } else {
                    cid
                };
                handle_init(cid, allocated_cid, payload)
            }
            CtapHidCommand::Ping => Response {
                cid,
                command: CtapHidCommand::Ping,
                payload: payload.to_vec(),
            },
            CtapHidCommand::Wink if payload.is_empty() => Response {
                cid,
                command: CtapHidCommand::Wink,
                payload: Vec::new(),
            },
            CtapHidCommand::Wink => error(cid, CtapHidError::Length),
            CtapHidCommand::Cbor => return self.queue_cbor(cid, payload),
            CtapHidCommand::Cancel => return self.cancel(cid, payload.len()),
            CtapHidCommand::Keepalive | CtapHidCommand::Error => error(cid, CtapHidError::Command),
        };
        PacketOutcome::Response(response)
    }

    fn active_cid(&self) -> Option<u32> {
        self.pending
            .as_ref()
            .map(|pending| pending.cid)
            .or_else(|| self.processing.as_ref().map(|processing| processing.cid))
    }

    fn abort_incomplete(&mut self, cid: u32) {
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.cid == cid)
        {
            self.pending = None;
        }
    }

    fn abort_transaction(&mut self) {
        self.pending = None;
        if let Some(processing) = self.processing.take() {
            processing.cancelled.store(true, Ordering::SeqCst);
        }
        let _ = self.worker_tx.send(WorkerCommand::CancelState);
    }

    fn cancel(&mut self, cid: u32, payload_len: usize) -> PacketOutcome {
        if payload_len != 0 {
            return PacketOutcome::Response(error(cid, CtapHidError::Length));
        }
        if let Some(processing) = self
            .processing
            .as_ref()
            .filter(|processing| processing.cid == cid)
        {
            processing.cancelled.store(true, Ordering::SeqCst);
            let _ = self.worker_tx.send(WorkerCommand::CancelState);
        }
        PacketOutcome::Ignored
    }

    fn queue_cbor(&mut self, cid: u32, payload: &[u8]) -> PacketOutcome {
        let id = self.next_transaction_id;
        self.next_transaction_id = self.next_transaction_id.wrapping_add(1).max(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let status = Arc::new(AtomicU8::new(KEEPALIVE_PROCESSING));
        if self
            .worker_tx
            .send(WorkerCommand::Cbor {
                id,
                cid,
                payload: payload.to_vec(),
                cancelled: cancelled.clone(),
                status: status.clone(),
            })
            .is_err()
        {
            return PacketOutcome::Response(error(cid, CtapHidError::Other));
        }
        self.processing = Some(ProcessingRequest {
            id,
            cid,
            cancelled,
            status,
            last_keepalive: Instant::now(),
        });
        PacketOutcome::Processing
    }

    pub fn poll(&mut self) -> Option<PacketOutcome> {
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.started_at.elapsed() >= TRANSACTION_TIMEOUT)
        {
            let cid = self.pending.take().expect("timed-out request").cid;
            return Some(PacketOutcome::Response(error(cid, CtapHidError::Timeout)));
        }

        while let Ok(result) = self.worker_rx.try_recv() {
            if let Some(processing) = self
                .processing
                .as_ref()
                .filter(|processing| processing.id == result.id)
            {
                let payload = if processing.cancelled.load(Ordering::SeqCst) {
                    vec![0x2d]
                } else {
                    result.payload
                };
                self.processing = None;
                return Some(PacketOutcome::Response(Response {
                    cid: result.cid,
                    command: CtapHidCommand::Cbor,
                    payload,
                }));
            }
        }

        let processing = self.processing.as_mut()?;
        if processing.last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
            processing.last_keepalive = Instant::now();
            return Some(PacketOutcome::Response(Response {
                cid: processing.cid,
                command: CtapHidCommand::Keepalive,
                payload: vec![processing.status.load(Ordering::SeqCst)],
            }));
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub cid: u32,
    pub command: CtapHidCommand,
    pub payload: Vec<u8>,
}

impl Response {
    pub fn packets(&self) -> Vec<[u8; REPORT_SIZE]> {
        encode_message(self.cid, self.command, &self.payload)
    }
}

pub fn handle_packet(report: &[u8]) -> Option<Response> {
    let mut handler = PacketHandler::default();
    match handler.handle_packet(report) {
        Some(PacketOutcome::Response(response)) => Some(response),
        Some(PacketOutcome::NeedMore | PacketOutcome::Processing | PacketOutcome::Ignored)
        | None => None,
    }
}

pub fn describe_report(report: &[u8]) -> String {
    if report.len() != REPORT_SIZE {
        return format!("invalid-size len={}", report.len());
    }

    let cid = u32::from_be_bytes(report[0..4].try_into().expect("fixed cid slice"));
    let packet_type = report[4];
    if packet_type & TYPE_INIT != 0 {
        let payload_len = u16::from_be_bytes([report[5], report[6]]) as usize;
        let cmd_byte = packet_type & !TYPE_INIT;
        let cmd_name = CtapHidCommand::from_byte(cmd_byte)
            .map(command_name)
            .unwrap_or("UNKNOWN");
        format!("init cid={cid:#010x} cmd={cmd_name}({cmd_byte:#04x}) payload_len={payload_len}",)
    } else {
        format!("cont cid={cid:#010x} seq={packet_type}")
    }
}

pub fn command_name(command: CtapHidCommand) -> &'static str {
    match command {
        CtapHidCommand::Ping => "PING",
        CtapHidCommand::Init => "INIT",
        CtapHidCommand::Wink => "WINK",
        CtapHidCommand::Cbor => "CBOR",
        CtapHidCommand::Cancel => "CANCEL",
        CtapHidCommand::Keepalive => "KEEPALIVE",
        CtapHidCommand::Error => "ERROR",
    }
}

fn handle_init(cid: u32, allocated_cid: u32, payload: &[u8]) -> Response {
    if payload.len() != 8 {
        return error(cid, CtapHidError::Length);
    }

    let mut response = Vec::with_capacity(17);
    response.extend_from_slice(payload);
    response.extend_from_slice(&allocated_cid.to_be_bytes());
    response.push(2); // CTAPHID protocol version.
    response.extend_from_slice(&[0, 1, 0]);
    response.push(CAPABILITY_WINK | CAPABILITY_CBOR | CAPABILITY_NMSG);

    Response {
        cid,
        command: CtapHidCommand::Init,
        payload: response,
    }
}

fn error(cid: u32, code: CtapHidError) -> Response {
    log::debug!(
        "ctaphid error cid={cid:#010x} code={code:?} value={:#04x}",
        code as u8
    );
    Response {
        cid,
        command: CtapHidCommand::Error,
        payload: vec![code as u8],
    }
}

fn encode_message(cid: u32, command: CtapHidCommand, payload: &[u8]) -> Vec<[u8; REPORT_SIZE]> {
    let mut packets = Vec::new();
    let mut first = [0u8; REPORT_SIZE];
    first[0..4].copy_from_slice(&cid.to_be_bytes());
    first[4] = command.byte() | TYPE_INIT;
    first[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());

    let first_len = payload.len().min(REPORT_SIZE - 7);
    first[7..7 + first_len].copy_from_slice(&payload[..first_len]);
    packets.push(first);

    let mut offset = first_len;
    let mut sequence = 0u8;
    while offset < payload.len() {
        let mut continuation = [0u8; REPORT_SIZE];
        continuation[0..4].copy_from_slice(&cid.to_be_bytes());
        continuation[4] = sequence;
        let chunk_len = (payload.len() - offset).min(REPORT_SIZE - 5);
        continuation[5..5 + chunk_len].copy_from_slice(&payload[offset..offset + chunk_len]);
        packets.push(continuation);
        offset += chunk_len;
        sequence = sequence.wrapping_add(1);
    }

    packets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command_packet(cid: u32, command: CtapHidCommand, payload: &[u8]) -> [u8; REPORT_SIZE] {
        let mut packet = [0u8; REPORT_SIZE];
        packet[0..4].copy_from_slice(&cid.to_be_bytes());
        packet[4] = command.byte() | TYPE_INIT;
        packet[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let first_len = payload.len().min(REPORT_SIZE - 7);
        packet[7..7 + first_len].copy_from_slice(&payload[..first_len]);
        packet
    }

    fn init_packet() -> [u8; REPORT_SIZE] {
        command_packet(BROADCAST_CID, CtapHidCommand::Init, b"12345678")
    }

    fn allocate_channel(handler: &mut PacketHandler) -> u32 {
        let Some(PacketOutcome::Response(response)) = handler.handle_packet(&init_packet()) else {
            panic!("expected INIT response");
        };
        u32::from_be_bytes(response.payload[8..12].try_into().expect("allocated CID"))
    }

    fn assert_error(response: Response, cid: u32, expected: CtapHidError) {
        assert_eq!(response.cid, cid);
        assert_eq!(response.command, CtapHidCommand::Error);
        assert_eq!(response.payload, vec![expected as u8]);
    }

    #[test]
    fn init_allocates_channel() {
        let response = handle_packet(&init_packet()).expect("response");
        assert_eq!(response.command, CtapHidCommand::Init);
        assert_eq!(&response.payload[0..8], b"12345678");
        assert_eq!(&response.payload[8..12], &1u32.to_be_bytes());
        assert_eq!(response.payload[12], 2);
        assert_eq!(
            response.payload[16],
            CAPABILITY_WINK | CAPABILITY_CBOR | CAPABILITY_NMSG
        );
    }

    #[test]
    fn continuation_packets_are_assembled() {
        let mut handler = PacketHandler::default();
        let cid = allocate_channel(&mut handler);
        let payload = vec![0xaa; 100];

        let mut first = [0u8; REPORT_SIZE];
        first[0..4].copy_from_slice(&cid.to_be_bytes());
        first[4] = CtapHidCommand::Ping.byte() | TYPE_INIT;
        first[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        first[7..].copy_from_slice(&payload[..REPORT_SIZE - 7]);

        let mut second = [0u8; REPORT_SIZE];
        second[0..4].copy_from_slice(&cid.to_be_bytes());
        second[4] = 0;
        second[5..5 + payload.len() - (REPORT_SIZE - 7)]
            .copy_from_slice(&payload[REPORT_SIZE - 7..]);

        assert_eq!(handler.handle_packet(&first), Some(PacketOutcome::NeedMore));
        let Some(PacketOutcome::Response(response)) = handler.handle_packet(&second) else {
            panic!("expected response");
        };
        assert_eq!(response.command, CtapHidCommand::Ping);
        assert_eq!(response.payload, payload);
    }

    #[test]
    fn ping_echoes_payload() {
        let mut handler = PacketHandler::default();
        let cid = allocate_channel(&mut handler);
        let packet = command_packet(cid, CtapHidCommand::Ping, b"abc");

        let Some(PacketOutcome::Response(response)) = handler.handle_packet(&packet) else {
            panic!("expected PING response");
        };
        assert_eq!(response.cid, cid);
        assert_eq!(response.command, CtapHidCommand::Ping);
        assert_eq!(response.payload, b"abc");
    }

    #[test]
    fn init_allocates_distinct_non_reserved_channels() {
        let mut handler = PacketHandler::default();
        let first = allocate_channel(&mut handler);
        let second = allocate_channel(&mut handler);
        assert_ne!(first, second);
        assert_ne!(first, 0);
        assert_ne!(first, BROADCAST_CID);
    }

    #[test]
    fn init_requires_an_eight_byte_nonce() {
        let mut handler = PacketHandler::default();
        let packet = command_packet(BROADCAST_CID, CtapHidCommand::Init, b"short");
        let Some(PacketOutcome::Response(response)) = handler.handle_packet(&packet) else {
            panic!("expected error response");
        };
        assert_error(response, BROADCAST_CID, CtapHidError::Length);
    }

    #[test]
    fn non_init_commands_reject_reserved_or_unallocated_channels() {
        let mut handler = PacketHandler::default();
        for cid in [0, 42, BROADCAST_CID] {
            let packet = command_packet(cid, CtapHidCommand::Ping, b"");
            let Some(PacketOutcome::Response(response)) = handler.handle_packet(&packet) else {
                panic!("expected error response");
            };
            assert_error(response, cid, CtapHidError::Channel);
        }
    }

    #[test]
    fn unknown_command_returns_invalid_command() {
        let mut handler = PacketHandler::default();
        let cid = allocate_channel(&mut handler);
        let mut packet = command_packet(cid, CtapHidCommand::Ping, b"");
        packet[4] = TYPE_INIT | 0x7e;
        let Some(PacketOutcome::Response(response)) = handler.handle_packet(&packet) else {
            panic!("expected error response");
        };
        assert_error(response, cid, CtapHidError::Command);
    }

    #[test]
    fn oversized_request_returns_invalid_length() {
        let mut handler = PacketHandler::default();
        let cid = allocate_channel(&mut handler);
        let mut packet = command_packet(cid, CtapHidCommand::Ping, b"");
        packet[5..7].copy_from_slice(&((MAX_PAYLOAD_SIZE + 1) as u16).to_be_bytes());
        let Some(PacketOutcome::Response(response)) = handler.handle_packet(&packet) else {
            panic!("expected error response");
        };
        assert_error(response, cid, CtapHidError::Length);
    }

    #[test]
    fn invalid_continuation_sequence_aborts_request() {
        let mut handler = PacketHandler::default();
        let cid = allocate_channel(&mut handler);
        let first = command_packet(cid, CtapHidCommand::Ping, &[0xaa; REPORT_SIZE]);
        assert_eq!(handler.handle_packet(&first), Some(PacketOutcome::NeedMore));

        let mut continuation = [0u8; REPORT_SIZE];
        continuation[0..4].copy_from_slice(&cid.to_be_bytes());
        continuation[4] = 1;
        let Some(PacketOutcome::Response(response)) = handler.handle_packet(&continuation) else {
            panic!("expected sequence error");
        };
        assert_error(response, cid, CtapHidError::Seq);

        continuation[4] = 0;
        assert_eq!(
            handler.handle_packet(&continuation),
            Some(PacketOutcome::Ignored),
            "spurious continuations are ignored after the request is aborted"
        );
    }

    #[test]
    fn transactions_are_global_and_init_resynchronizes_the_active_channel() {
        let mut handler = PacketHandler::default();
        let active_cid = allocate_channel(&mut handler);
        let other_cid = allocate_channel(&mut handler);
        let partial = command_packet(active_cid, CtapHidCommand::Ping, &[0xaa; REPORT_SIZE]);
        assert_eq!(
            handler.handle_packet(&partial),
            Some(PacketOutcome::NeedMore)
        );

        let other = command_packet(other_cid, CtapHidCommand::Ping, b"");
        let Some(PacketOutcome::Response(response)) = handler.handle_packet(&other) else {
            panic!("expected channel-busy response");
        };
        assert_error(response, other_cid, CtapHidError::Busy);

        let resynchronize = command_packet(active_cid, CtapHidCommand::Init, b"12345678");
        let Some(PacketOutcome::Response(response)) = handler.handle_packet(&resynchronize) else {
            panic!("expected resynchronization response");
        };
        assert_eq!(response.command, CtapHidCommand::Init);
        assert_eq!(&response.payload[8..12], &active_cid.to_be_bytes());
        assert!(handler.pending.is_none());
    }

    #[test]
    fn incomplete_transactions_time_out() {
        let mut handler = PacketHandler::default();
        let cid = allocate_channel(&mut handler);
        let partial = command_packet(cid, CtapHidCommand::Ping, &[0xaa; REPORT_SIZE]);
        assert_eq!(
            handler.handle_packet(&partial),
            Some(PacketOutcome::NeedMore)
        );
        handler
            .pending
            .as_mut()
            .expect("pending request")
            .started_at = Instant::now() - TRANSACTION_TIMEOUT;

        let Some(PacketOutcome::Response(response)) = handler.poll() else {
            panic!("expected timeout response");
        };
        assert_error(response, cid, CtapHidError::Timeout);
        assert!(handler.pending.is_none());
    }

    struct PendingApproval;

    impl crate::approval::UserApproval for PendingApproval {
        fn approve(&self, _: &str) -> bool {
            panic!("CTAP must use the controlled approval API")
        }

        fn approve_controlled(
            &self,
            _: &str,
            control: &crate::approval::ApprovalControl,
        ) -> crate::approval::ApprovalOutcome {
            // Never approves itself: only transaction cancellation/deadline can
            // release the worker. A fixed sleep would not verify cancellation.
            loop {
                if let Some(outcome) = control.stopped() {
                    return outcome;
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
    }

    #[test]
    fn cbor_processing_emits_keepalive_and_cancel_has_no_direct_response() {
        let store_dir =
            std::env::temp_dir().join(format!("tpm-passkey-ctaphid-cancel-{}", std::process::id()));
        let mut handler = PacketHandler::new_with_user_approval(
            store_dir.clone(),
            None,
            Box::new(PendingApproval),
        );
        let cid = allocate_channel(&mut handler);
        let selection = command_packet(
            cid,
            CtapHidCommand::Cbor,
            &[ctap2::Ctap2Command::Selection.into()],
        );
        assert_eq!(
            handler.handle_packet(&selection),
            Some(PacketOutcome::Processing)
        );

        thread::sleep(KEEPALIVE_INTERVAL + Duration::from_millis(20));
        let Some(PacketOutcome::Response(keepalive)) = handler.poll() else {
            panic!("expected keepalive");
        };
        assert_eq!(keepalive.command, CtapHidCommand::Keepalive);
        assert_eq!(keepalive.payload, vec![2]);

        let cancel = command_packet(cid, CtapHidCommand::Cancel, b"");
        assert_eq!(handler.handle_packet(&cancel), Some(PacketOutcome::Ignored));

        fn wait_cbor(handler: &mut PacketHandler) -> Response {
            let deadline = Instant::now() + Duration::from_millis(500);
            loop {
                if let Some(PacketOutcome::Response(response)) = handler.poll()
                    && response.command == CtapHidCommand::Cbor
                {
                    return response;
                }
                assert!(
                    Instant::now() < deadline,
                    "worker did not become responsive"
                );
                thread::sleep(Duration::from_millis(5));
            }
        }
        let cancelled = wait_cbor(&mut handler);
        assert_eq!(cancelled.payload, vec![0x2d]);
        // CANCEL must actually free the worker for a subsequent transaction.
        let info = command_packet(
            cid,
            CtapHidCommand::Cbor,
            &[ctap2::Ctap2Command::GetInfo.into()],
        );
        assert_eq!(
            handler.handle_packet(&info),
            Some(PacketOutcome::Processing)
        );
        assert_eq!(wait_cbor(&mut handler).payload[0], 0);
        let _ = std::fs::remove_dir_all(store_dir);
    }

    #[test]
    fn response_fragmentation_preserves_payload_and_sequence_numbers() {
        let payload = vec![0x5a; 200];
        let packets = encode_message(9, CtapHidCommand::Ping, &payload);
        assert_eq!(packets.len(), 4);
        assert_eq!(packets[0][4], TYPE_INIT | CtapHidCommand::Ping.byte());
        assert_eq!(&packets[0][5..7], &(payload.len() as u16).to_be_bytes());
        assert_eq!(packets[1][4], 0);
        assert_eq!(packets[2][4], 1);
        assert_eq!(packets[3][4], 2);

        let mut reconstructed = packets[0][7..].to_vec();
        for packet in &packets[1..] {
            reconstructed.extend_from_slice(&packet[5..]);
        }
        reconstructed.truncate(payload.len());
        assert_eq!(reconstructed, payload);
    }
}
