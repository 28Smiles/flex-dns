use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Child DNS Key (CDNSKEY) Record
/// This record is
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct CdnsKey<'a> {
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

impl<'a> RDataParse<'a> for CdnsKey<'a> {
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
            public_key
        })
    }
}

impl<'a> WriteBytes for CdnsKey<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
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
        5,
        [
            0x01, 0x02, // flags
            0x03, // protocol
            0x04, // algorithm
            0x00, // public key
        ],
        CdnsKey {
            flags: 0x0102,
            protocol: 0x03,
            algorithm: 0x04,
            public_key: unsafe { Characters::new_unchecked(&[]) },
        },
    );
}