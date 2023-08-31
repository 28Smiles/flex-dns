use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Uniform resource identifier record (URI)
/// This record is used to publish mappings from hostnames to URIs.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Uri<'a> {
    /// The priority of this URI record. Lower values are preferred.
    pub priority: u16,
    /// The weight of this URI record. Higher values are preferred.
    pub weight: u16,
    /// The target URI.
    pub target: Characters<'a>,
}

impl<'a> RDataParse<'a> for Uri<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let priority = u16::parse(rdata, i)?;
        let weight = u16::parse(rdata, i)?;
        let target = Characters::parse(rdata, i)?;

        Ok(Self {
            priority,
            weight,
            target,
        })
    }
}

impl<'a> WriteBytes for Uri<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.priority.write(message)?;
        bytes += self.weight.write(message)?;
        bytes += self.target.write(message)?;

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
            0x00, 0x0e, // priority
            0x00, 0x0e, // weight
            0x03, // length of "www"
            b'w', b'w', b'w', // "www"
        ],
        Uri {
            priority: 14,
            weight: 14,
            target: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}