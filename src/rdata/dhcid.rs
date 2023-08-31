use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Dynamic host configuration protocol record
/// This record is used to store DHCP information.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct DhcId<'a> {
    /// The identifier type.
    pub type_: u16,
    /// The digest type.
    pub digest_type: u8,
    /// The digest of the DHCP information.
    pub digest: Characters<'a>,
}

impl<'a> RDataParse<'a> for DhcId<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let type_ = u16::parse(rdata, i)?;
        let digest_type = u8::parse(rdata, i)?;
        let digest = Characters::parse(rdata, i)?;

        Ok(Self {
            type_,
            digest_type,
            digest,
        })
    }
}

impl<'a> WriteBytes for DhcId<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.type_.write(message)?;
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
        7,
        [
            0x00, 0x0e, // type
            0x03, // digest type
            0x03, // digest len
            b'w', b'w', b'w', // digest
        ],
        DhcId {
            type_: 14,
            digest_type: 3,
            digest: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
