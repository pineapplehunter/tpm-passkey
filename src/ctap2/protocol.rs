#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Ctap2Command {
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    GetInfo = 0x04,
    ClientPin = 0x06,
    GetNextAssertion = 0x08,
    Reset = 0x07,
    CredentialManagement = 0x0a,
    Selection = 0x0b,
    BioEnrollment = 0x09,
    LargeBlobs = 0x0c,
    Config = 0x0d,
    BioEnrollmentPreview = 0x40,
    CredentialManagementPreview = 0x41,
}

#[derive(Debug)]
pub struct UnknownCtapCommandError;

impl std::fmt::Display for UnknownCtapCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for UnknownCtapCommandError {}

impl TryFrom<u8> for Ctap2Command {
    type Error = UnknownCtapCommandError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x01 => Self::MakeCredential,
            0x02 => Self::GetAssertion,
            0x04 => Self::GetInfo,
            0x06 => Self::ClientPin,
            0x07 => Self::Reset,
            0x08 => Self::GetNextAssertion,
            0x09 => Self::BioEnrollment,
            0x0a => Self::CredentialManagement,
            0x0b => Self::Selection,
            0x0c => Self::LargeBlobs,
            0x0d => Self::Config,
            0x40 => Self::BioEnrollmentPreview,
            0x41 => Self::CredentialManagementPreview,
            _ => return Err(UnknownCtapCommandError),
        })
    }
}

impl From<Ctap2Command> for u8 {
    fn from(value: Ctap2Command) -> Self {
        value as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum ErrorStatus {
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    CredentialExcluded = 0x19,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    UnsupportedOption = 0x2b,
    NoCredentials = 0x2e,
    PinInvalid = 0x31,
    PinBlocked = 0x32,
    PinAuthInvalid = 0x33,
    PinNotSet = 0x35,
    PinPolicyViolation = 0x37,
}

impl From<ErrorStatus> for u8 {
    fn from(status: ErrorStatus) -> Self {
        status as u8
    }
}

pub fn command_name(command: Ctap2Command) -> &'static str {
    match command {
        Ctap2Command::MakeCredential => "authenticatorMakeCredential",
        Ctap2Command::GetAssertion => "authenticatorGetAssertion",
        Ctap2Command::GetNextAssertion => "authenticatorGetNextAssertion",
        Ctap2Command::GetInfo => "authenticatorGetInfo",
        Ctap2Command::ClientPin => "authenticatorClientPIN",
        Ctap2Command::CredentialManagement | Ctap2Command::CredentialManagementPreview => {
            "authenticatorCredentialManagement"
        }
        Ctap2Command::Reset => "authenticatorReset",
        Ctap2Command::Selection => "authenticatorSelection",
        Ctap2Command::BioEnrollment | Ctap2Command::BioEnrollmentPreview => {
            "authenticatorBioEnrollment"
        }
        Ctap2Command::LargeBlobs => "authenticatorLargeBlobs",
        Ctap2Command::Config => "authenticatorConfig",
    }
}
