use uhid_virt::{Bus, CreateParams};

pub const REPORT_SIZE: usize = 64;
pub const FIDO_USAGE_PAGE: u16 = 0xf1d0;
pub const FIDO_USAGE_CTAPHID: u8 = 0x01;

const VENDOR_ID: u32 = 0x1209;
const PRODUCT_ID: u32 = 0xf1d0;

// FIDO CTAPHID descriptor: usage page 0xF1D0, usage 0x01, one 64-byte input
// report and one 64-byte output report. Browsers use this usage pair for
// authenticator discovery.
pub const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xd0, 0xf1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (CTAPHID)
    0xa1, 0x01, // Collection (Application)
    0x09, 0x20, // Usage (Data In)
    0x15, 0x00, // Logical Minimum (0)
    0x26, 0xff, 0x00, // Logical Maximum (255)
    0x75, 0x08, // Report Size (8)
    0x95, 0x40, // Report Count (64)
    0x81, 0x02, // Input (Data, Variable, Absolute)
    0x09, 0x21, // Usage (Data Out)
    0x15, 0x00, // Logical Minimum (0)
    0x26, 0xff, 0x00, // Logical Maximum (255)
    0x75, 0x08, // Report Size (8)
    0x95, 0x40, // Report Count (64)
    0x91, 0x02, // Output (Data, Variable, Absolute)
    0xc0, // End Collection
];

pub fn create_params() -> CreateParams {
    CreateParams {
        name: "tpm-passkey".to_owned(),
        phys: "tpm-passkey/uhid".to_owned(),
        uniq: "tpm-passkey-dev".to_owned(),
        bus: Bus::USB,
        vendor: VENDOR_ID,
        product: PRODUCT_ID,
        version: 1,
        country: 0,
        rd_data: FIDO_REPORT_DESCRIPTOR.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_uses_fido_usage() {
        assert!(
            FIDO_REPORT_DESCRIPTOR
                .windows(3)
                .any(|w| w == [0x06, 0xd0, 0xf1])
        );
        assert!(
            FIDO_REPORT_DESCRIPTOR
                .windows(2)
                .any(|w| w == [0x09, FIDO_USAGE_CTAPHID])
        );
    }

    #[test]
    fn descriptor_uses_64_byte_reports() {
        assert!(
            FIDO_REPORT_DESCRIPTOR
                .windows(2)
                .any(|w| w == [0x95, REPORT_SIZE as u8])
        );
    }
}
