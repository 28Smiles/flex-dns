use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::characters::Characters;
use crate::name::DnsName;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Signature
/// This record is used to authenticate the data in a message
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Sig<'a> {
    /// The type of the record covered by this signature
    pub type_covered: u16,
    /// The algorithm used
    pub algorithm: u8,
    /// The number of labels in the original RDATA
    pub labels: u8,
    /// The original TTL
    pub original_ttl: u32,
    /// The signature expiration
    pub signature_expiration: u32,
    /// The signature inception
    pub signature_inception: u32,
    /// The key tag
    pub key_tag: u16,
    /// The signer's name
    pub signer_name: DnsName<'a>,
    /// The signature
    pub signature: Characters<'a>,
}

impl<'a> RDataParse<'a> for Sig<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let type_covered = u16::parse(rdata, i)?;
        let algorithm = u8::parse(rdata, i)?;
        let labels = u8::parse(rdata, i)?;
        let original_ttl = u32::parse(rdata, i)?;
        let signature_expiration = u32::parse(rdata, i)?;
        let signature_inception = u32::parse(rdata, i)?;
        let key_tag = u16::parse(rdata, i)?;
        let signer_name = DnsName::parse(rdata, i)?;
        let signature = Characters::parse(rdata, i)?;

        Ok(Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        })
    }
}

impl<'a> WriteBytes for Sig<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.type_covered.write(message)?;
        bytes += self.algorithm.write(message)?;
        bytes += self.labels.write(message)?;
        bytes += self.original_ttl.write(message)?;
        bytes += self.signature_expiration.write(message)?;
        bytes += self.signature_inception.write(message)?;
        bytes += self.key_tag.write(message)?;
        bytes += self.signer_name.write(message)?;
        bytes += self.signature.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        43,
        [
            0x00, 0x0e, // type covered
            0x05, // algorithm
            0x06, // labels
            0x00, 0x00, 0x00, 0x0a, // original ttl
            0x00, 0x00, 0x00, 0x0b, // signature expiration
            0x00, 0x00, 0x00, 0x0c, // signature inception
            0x00, 0x0d, // key tag
            0x03, b'w', b'w', b'w',
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // signer name
            0x07, b'f', b'o', b'o', b'-', b'b', b'a', b'r', // signature
        ],
        Sig {
            type_covered: 14,
            algorithm: 5,
            labels: 6,
            original_ttl: 10,
            signature_expiration: 11,
            signature_inception: 12,
            key_tag: 13,
            signer_name: unsafe { DnsName::new_unchecked(b"\x03www\x07example\x03com\x00") },
            signature: unsafe { Characters::new_unchecked(b"foo-bar") },
        },
    );
}
