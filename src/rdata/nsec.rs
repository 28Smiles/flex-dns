use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::name::DnsName;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Next secure record
/// This record is used to prove that a name does not exist in a zone.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Nsec<'a> {
    /// The next owner name in the canonical ordering of the zone.
    pub next_domain_name: DnsName<'a>,
    /// The set of RR types present at the NSEC RR's owner name.
    pub type_bit_maps: Characters<'a>,
}

impl<'a> RDataParse<'a> for Nsec<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let next_domain_name = DnsName::parse(rdata, i)?;
        let type_bit_maps = Characters::parse(rdata, i)?;

        Ok(Self {
            next_domain_name,
            type_bit_maps,
        })
    }
}

impl<'a> WriteBytes for Nsec<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.next_domain_name.write(message)?;
        bytes += self.type_bit_maps.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        9,
        [
            0x03, // length of "www"
            b'w', b'w', b'w', // "www"
            0x00, // end of name
            0x03, // length of "www"
            b'w', b'w', b'w', // "www"
        ],
        Nsec {
            next_domain_name: unsafe { DnsName::new_unchecked(b"\x03www\x00") },
            type_bit_maps: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
