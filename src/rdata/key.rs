use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Key
/// This record is used to store a public key that can be used to verify DNSSEC signatures
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Key<'a> {
    /// The flags field is used to store flags specific to the algorithm
    pub flags: u16,
    /// The protocol field is used to store the protocol number for which this key is used
    pub protocol: u8,
    /// The algorithm field is used to store the algorithm number for this key
    pub algorithm: u8,
    /// The public key is stored as a character string
    pub public_key: Characters<'a>,
}

impl<'a> RDataParse<'a> for Key<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let flags = u16::parse(rdata, i)?;
        let protocol = u8::parse(rdata, i)?;
        let algorithm = u8::parse(rdata, i)?;
        let public_key = Characters::parse(rdata, i)?;

        Ok(Self {
            flags,
            protocol,
            algorithm,
            public_key,
        })
    }
}

impl<'a> WriteBytes for Key<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.flags.write(message)?;
        bytes += self.protocol.write(message)?;
        bytes += self.algorithm.write(message)?;
        bytes += self.public_key.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        8,
        [
            0x00, 0x0e, // flags
            0xc4, // protocol
            0x4c, // algorithm
            0x03, // length
            b'w', b'w', b'w', // "www"
        ],
        Key {
            flags: 14,
            protocol: 196,
            algorithm: 76,
            public_key: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
