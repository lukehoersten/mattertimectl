//! Manual pairing code decoding (Matter Core spec 5.1.4.1).
//!
//! An 11-digit (no VID/PID) or 21-digit (with VID/PID) decimal code packs a
//! 4-bit short discriminator and the 27-bit setup passcode, guarded by a
//! trailing Verhoeff check digit. QR payloads ("MT:...") are not accepted;
//! the primary ecosystem always shows the numeric code.

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PairingCodeError {
    #[error(
        "QR payloads are not supported; enter the numeric pairing code shown by the primary ecosystem"
    )]
    QrPayload,
    #[error("pairing code must be 11 or 21 digits (got {0})")]
    BadLength(usize),
    #[error("pairing code check digit is wrong; re-check the digits")]
    BadCheckDigit,
    #[error("pairing code decodes to an invalid setup passcode")]
    BadPasscode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Onboarding {
    pub passcode: u32,
    /// Upper 4 bits of the 12-bit discriminator, as carried in manual codes.
    pub short_discriminator: u8,
}

/// Setup passcodes the spec forbids (trivial/sequential values).
const INVALID_PASSCODES: [u32; 12] = [
    0, 11111111, 22222222, 33333333, 44444444, 55555555, 66666666, 77777777, 88888888, 99999999,
    12345678, 87654321,
];

pub fn parse_manual_code(raw: &str) -> Result<Onboarding, PairingCodeError> {
    let trimmed = raw.trim();
    if trimmed.starts_with("MT:") {
        return Err(PairingCodeError::QrPayload);
    }
    let digits: Vec<u8> = trimmed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| {
            c.to_digit(10)
                .map(|d| d as u8)
                .ok_or(PairingCodeError::BadLength(0))
        })
        .collect::<Result<_, _>>()
        .map_err(|_| PairingCodeError::BadLength(trimmed.len()))?;

    if digits.len() != 11 && digits.len() != 21 {
        return Err(PairingCodeError::BadLength(digits.len()));
    }

    let payload: String = digits[..digits.len() - 1]
        .iter()
        .map(|d| (b'0' + d) as char)
        .collect();
    if verhoeff::calculate(payload.as_str()) != digits[digits.len() - 1] {
        return Err(PairingCodeError::BadCheckDigit);
    }

    let d1 = u32::from(digits[0]);
    let chunk2 = digits[1..6]
        .iter()
        .fold(0u32, |acc, &d| acc * 10 + u32::from(d));
    let chunk3 = digits[6..10]
        .iter()
        .fold(0u32, |acc, &d| acc * 10 + u32::from(d));

    // digit 1  = (VID_PID_PRESENT << 2) | (discriminator >> 10)
    // digits 2-6 = ((discriminator & 0x300) << 6) | (passcode & 0x3FFF)
    // digits 7-10 = passcode >> 14
    let short_discriminator = (((d1 & 0x3) << 2) | ((chunk2 >> 14) & 0x3)) as u8;
    let passcode = (chunk3 << 14) | (chunk2 & 0x3FFF);

    if passcode >= 1 << 27 || INVALID_PASSCODES.contains(&passcode) {
        return Err(PairingCodeError::BadPasscode);
    }
    Ok(Onboarding {
        passcode,
        short_discriminator,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_the_canonical_test_code() {
        // The Matter SDK test onboarding payload: passcode 20202021,
        // discriminator 3840 (0xF00) => short discriminator 15, manual code
        // 34970112332.
        let onboarding = parse_manual_code("34970112332").unwrap();
        assert_eq!(
            onboarding,
            Onboarding {
                passcode: 20202021,
                short_discriminator: 15,
            }
        );
    }

    #[test]
    fn accepts_hyphenated_input() {
        assert!(parse_manual_code("3497-011-2332").is_ok());
    }

    #[test]
    fn rejects_qr_payloads_with_guidance() {
        assert_eq!(
            parse_manual_code("MT:Y.K90SO527JA0648G00"),
            Err(PairingCodeError::QrPayload)
        );
    }

    #[test]
    fn rejects_wrong_lengths_and_check_digits() {
        assert!(matches!(
            parse_manual_code("1234"),
            Err(PairingCodeError::BadLength(_))
        ));
        assert_eq!(
            parse_manual_code("34970112331"),
            Err(PairingCodeError::BadCheckDigit)
        );
    }
}
