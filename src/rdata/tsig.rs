use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::name::DnsName;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Transaction signature record (TSIG)
/// This record is used to authenticate dynamic updates as coming from an
/// approved client, and to authenticate responses as coming from an approved
/// recursive server.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct TSig<'a> {
    /// The name of the algorithm in domain name syntax.
    pub algorithm: DnsName<'a>,
    /// The time that the signature was generated.
    pub time_signed: u64,
    /// The Fudge value is an unsigned 8-bit field that specifies the allowed
    /// time difference in seconds.
    pub fudge: u8,
    /// The MAC is a variable length octet string containing the message
    /// authentication code.
    pub mac: Characters<'a>,
    /// The original ID of the message.
    pub original_id: u16,
    /// The error field is an unsigned 16-bit field that contains the extended
    /// RCODE covering TSIG processing.
    pub error: u16,
    /// The other field is a variable length octet string that contains
    /// information that may be used by the server to complete the transaction.
    pub other: Characters<'a>,
}

impl<'a> RDataParse<'a> for TSig<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let algorithm = DnsName::parse(rdata, i)?;
        let time_signed = u64::parse(rdata, i)?;
        let fudge = u8::parse(rdata, i)?;
        let mac = Characters::parse(rdata, i)?;
        let original_id = u16::parse(rdata, i)?;
        let error = u16::parse(rdata, i)?;
        let other = Characters::parse(rdata, i)?;

        Ok(Self {
            algorithm,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other,
        })
    }
}

impl<'a> WriteBytes for TSig<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.algorithm.write(message)?;
        bytes += self.time_signed.write(message)?;
        bytes += self.fudge.write(message)?;
        bytes += self.mac.write(message)?;
        bytes += self.original_id.write(message)?;
        bytes += self.error.write(message)?;
        bytes += self.other.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        26,
        [
            0x03, b'w', b'w', b'w', 0x00, // algorithm
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, // time_signed
            0x0b, // fudge
            0x03, 0x77, 0x77, 0x77, // mac
            0x00, 0x0c, // original_id
            0x00, 0x0d, // error
            0x03, 0x77, 0x77, 0x77, // other
        ],
        TSig {
            algorithm: unsafe { DnsName::new_unchecked(b"\x03www\x00") },
            time_signed: 10,
            fudge: 11,
            mac: unsafe { Characters::new_unchecked(b"www") },
            original_id: 12,
            error: 13,
            other: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
