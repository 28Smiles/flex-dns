use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # DNSSEC lookaside validation record (DLV)
/// This record is used to publish the public key of a DNSSEC lookaside validation
/// (DLV) trust anchor.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Dlv<'a> {
    /// key_tag is a mechanism for quickly identifying the signing key in a zone
    pub key_tag: u16,
    /// algorithm is the algorithm of the key
    pub algorithm: u8,
    /// digest_type is the algorithm used to construct the digest
    pub digest_type: u8,
    /// digest is the digest of the public key
    pub digest: Characters<'a>,
}

impl<'a> RDataParse<'a> for Dlv<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let key_tag = u16::parse(rdata, i)?;
        let algorithm = u8::parse(rdata, i)?;
        let digest_type = u8::parse(rdata, i)?;
        let digest = Characters::parse(rdata, i)?;

        Ok(Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }
}

impl<'a> WriteBytes for Dlv<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.key_tag.write(message)?;
        bytes += self.algorithm.write(message)?;
        bytes += self.digest_type.write(message)?;
        bytes += self.digest.write(message)?;

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
            0x00, 0x0e, // key_tag
            0x03, // algorithm
            0x03, // digest_type
            0x03, // digest len
            b'w', b'w', b'w', // digest
        ],
        Dlv {
            key_tag: 14,
            algorithm: 3,
            digest_type: 3,
            digest: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
