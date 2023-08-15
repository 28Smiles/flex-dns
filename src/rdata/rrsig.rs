use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::name::DnsName;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # DNSSEC signature record
/// This record is used to sign other records. It is used in conjunction with the
/// DnsKey record to verify the authenticity of a record.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct RRSig<'a> {
    /// The type of record that is covered by this signature.
    pub type_covered: u16,
    /// The algorithm used to create the signature.
    pub algorithm: u8,
    /// The number of seconds the signature is valid for.
    pub original_ttl: u32,
    /// The time at which the signature was created.
    pub signature_expiration: u32,
    /// The time at which the signature was last refreshed.
    pub signature_inception: u32,
    /// The key tag of the key that was used to create the signature.
    pub key_tag: u16,
    /// The name of the zone that this signature was created for.
    pub signer_name: DnsName<'a>,
    /// The signature.
    pub signature: Characters<'a>,
}

impl<'a> RDataParse<'a> for RRSig<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let type_covered = u16::parse(rdata.buffer, i)?;
        let algorithm = u8::parse(rdata.buffer, i)?;
        let original_ttl = u32::parse(rdata.buffer, i)?;
        let signature_expiration = u32::parse(rdata.buffer, i)?;
        let signature_inception = u32::parse(rdata.buffer, i)?;
        let key_tag = u16::parse(rdata.buffer, i)?;
        let signer_name = DnsName::parse(rdata.buffer, i)?;
        let signature = Characters::parse(rdata.buffer, i)?;

        Ok(Self {
            type_covered,
            algorithm,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        })
    }
}

impl<'a> WriteBytes for RRSig<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.type_covered.write(message)?;
        bytes += self.algorithm.write(message)?;
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
        42,
        [
            0x00, 0x0e, // type covered
            0x05, // algorithm
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
        RRSig {
            type_covered: 14,
            algorithm: 5,
            original_ttl: 10,
            signature_expiration: 11,
            signature_inception: 12,
            key_tag: 13,
            signer_name: unsafe { DnsName::new_unchecked(b"\x03www\x07example\x03com\x00") },
            signature: unsafe { Characters::new_unchecked(b"foo-bar") },
        },
    );
}
