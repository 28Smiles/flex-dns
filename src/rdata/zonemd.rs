use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Message digest for DNS zone record (ZONEMD)
/// This record is used to publish a message digest for a DNS zone.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ZoneMd<'a> {
    /// algorithm is the algorithm of the digest
    pub algorithm: u8,
    /// digest_type is the algorithm used to construct the digest
    pub digest_type: u8,
    /// digest is the digest of the zone
    pub digest: Characters<'a>,
}

impl<'a> RDataParse<'a> for ZoneMd<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let algorithm = u8::parse(rdata, i)?;
        let digest_type = u8::parse(rdata, i)?;
        let digest = Characters::parse(rdata, i)?;

        Ok(Self {
            algorithm,
            digest_type,
            digest
        })
    }
}

impl<'a> WriteBytes for ZoneMd<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

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
        6,
        [
            0x0e, // algorithm
            0x00, // digest_type
            0x03, // digest length
            b'w', b'w', b'w', // digest
        ],
        ZoneMd {
            algorithm: 14,
            digest_type: 0,
            digest: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}