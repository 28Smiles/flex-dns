use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Delegation signer record
/// This record is used to store a cryptographic hash of a DNSKEY record.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Ds<'a> {
    /// The key tag of the DNSKEY record.
    pub key_tag: u16,
    /// The algorithm of the DNSKEY record.
    pub algorithm: u8,
    /// The digest type of the DNSKEY record.
    pub digest_type: u8,
    /// The digest of the DNSKEY record.
    pub digest: Characters<'a>,
}

impl<'a> RDataParse<'a> for Ds<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let key_tag = u16::parse(rdata.buffer, i)?;
        let algorithm = u8::parse(rdata.buffer, i)?;
        let digest_type = u8::parse(rdata.buffer, i)?;
        let digest = Characters::parse(rdata.buffer, i)?;

        Ok(Ds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }
}

impl<'a> WriteBytes for Ds<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
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
            0x0c, 0x07, // key tag
            0x83, // algorithm
            0x73, // digest type
            0x03, // digest len
            b'w', b'w', b'w', // digest
        ],
        Ds {
            key_tag: 0x0c07,
            algorithm: 0x83,
            digest_type: 0x73,
            digest: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
