use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Child Delegation Signer (CDS) Record
/// This record is used to publish the key tag, algorithm, and digest type
/// used in the DS record of a child zone.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Cds<'a> {
    /// The key tag of the key that is being published.
    pub key_tag: u16,
    /// The algorithm of the key that is being published.
    pub algorithm: u8,
    /// The digest type of the key that is being published.
    pub digest_type: u8,
    /// The digest of the key that is being published.
    pub digest: Characters<'a>,
}

impl<'a> RDataParse<'a> for Cds<'a> {
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

impl<'a> WriteBytes for Cds<'a> {
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
        5,
        [ 0x00, 0x01, 0x08, 0x01, 0x00 ],
        Cds {
            key_tag: 1,
            algorithm: 8,
            digest_type: 1,
            digest: unsafe { Characters::new_unchecked(&[]) },
        },
    );
}
