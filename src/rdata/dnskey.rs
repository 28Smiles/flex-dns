use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # DNS key record
/// This record is used to store public keys that are associated with a zone.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct DnsKey<'a> {
    /// The flags field specifies various flags that control the security
    /// related aspects of the key.
    pub flags: u16,
    /// The protocol field specifies the protocol for which the key is used.
    pub protocol: u8,
    /// The algorithm field specifies the public key's cryptographic algorithm
    pub algorithm: u8,
    /// The public key field holds the public key material.
    pub public_key: Characters<'a>
}

impl<'a> RDataParse<'a> for DnsKey<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let flags = u16::parse(rdata, i)?;
        let protocol = u8::parse(rdata, i)?;
        let algorithm = u8::parse(rdata, i)?;
        let public_key = Characters::parse(rdata, i)?;

        Ok(DnsKey {
            flags,
            protocol,
            algorithm,
            public_key
        })
    }
}

impl<'a> WriteBytes for DnsKey<'a> {
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
            0x0f, 0x0e, // flags
            0x5c, // protocol
            0x8a, // algorithm
            0x03, // public key length
            b'w', b'w', b'w', // public key
        ],
        DnsKey {
            flags: 0x0f0e,
            protocol: 0x5c,
            algorithm: 0x8a,
            public_key: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
