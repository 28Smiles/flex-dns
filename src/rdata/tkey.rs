use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::characters::Characters;
use crate::name::DnsName;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Transaction key record (TKEY)
/// This record is used to establish a shared key between two hosts.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct TKey<'a> {
    /// The algorithm used to generate the key.
    pub algorithm: DnsName<'a>,
    /// The time the key was generated.
    pub inception: u32,
    /// The time the key will expire.
    pub expiration: u32,
    /// The mode of the key.
    pub mode: u16,
    /// The error that occurred.
    pub error: u16,
    /// The key data.
    pub key: Characters<'a>,
    /// The other data.
    pub other: Characters<'a>,
}

impl<'a> RDataParse<'a> for TKey<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let algorithm = DnsName::parse(rdata.buffer, i)?;
        let inception = u32::parse(rdata.buffer, i)?;
        let expiration = u32::parse(rdata.buffer, i)?;
        let mode = u16::parse(rdata.buffer, i)?;
        let error = u16::parse(rdata.buffer, i)?;
        let key = Characters::parse(rdata.buffer, i)?;
        let other = Characters::parse(rdata.buffer, i)?;

        Ok(Self {
            algorithm,
            inception,
            expiration,
            mode,
            error,
            key,
            other,
        })
    }
}

impl<'a> WriteBytes for TKey<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.algorithm.write(message)?;
        bytes += self.inception.write(message)?;
        bytes += self.expiration.write(message)?;
        bytes += self.mode.write(message)?;
        bytes += self.error.write(message)?;
        bytes += self.key.write(message)?;
        bytes += self.other.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        25,
        [
            0x03, b'w', b'w', b'w', 0x00, // algorithm
            0x00, 0x00, 0x00, 0x0a, // inception
            0x00, 0x00, 0x00, 0x0b, // expiration
            0x00, 0x0c, // mode
            0x00, 0x0d, // error
            0x03, b'w', b'w', b'w', // key
            0x03, b'w', b'w', b'w', // other
        ],
        TKey {
            algorithm: unsafe { DnsName::new_unchecked(b"\x03www\x00") },
            inception: 10,
            expiration: 11,
            mode: 12,
            error: 13,
            key: unsafe { Characters::new_unchecked(b"www") },
            other: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
