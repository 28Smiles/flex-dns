use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # SSH public key fingerprint record
/// This record is used to store the fingerprint of an SSH public key.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct SshFp<'a> {
    /// The algorithm used to generate the fingerprint.
    pub algorithm: u8,
    /// The fingerprint type.
    pub fingerprint_type: u8,
    /// The fingerprint data.
    pub data: Characters<'a>,
}

impl<'a> RDataParse<'a> for SshFp<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let algorithm = u8::parse(rdata.buffer, i)?;
        let fingerprint_type = u8::parse(rdata.buffer, i)?;
        let data = Characters::parse(rdata.buffer, i)?;

        Ok(Self {
            algorithm,
            fingerprint_type,
            data,
        })
    }
}

impl<'a> WriteBytes for SshFp<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.algorithm.write(message)?;
        bytes += self.fingerprint_type.write(message)?;
        bytes += self.data.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        6,
        [
            0x01, // algorithm
            0x02, // fingerprint type
            0x03, // length of "www"
            b'w', b'w', b'w', // "www"
        ],
        SshFp {
            algorithm: 1,
            fingerprint_type: 2,
            data: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
