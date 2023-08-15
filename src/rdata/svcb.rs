use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::name::DnsName;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Service binding record (SVCB)
/// This record is used to describe the parameters of a service binding.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Svcb<'a> {
    /// The priority of this target host
    pub priority: u16,
    /// The relative weight for entries with the same priority
    pub weight: u16,
    /// The TCP or UDP port on which the service is to be found
    pub port: u16,
    /// The domain name of the target host
    pub target: DnsName<'a>,
    /// The parameters of the service binding
    pub parameters: Characters<'a>,
}

impl<'a> RDataParse<'a> for Svcb<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let priority = u16::parse(rdata, i)?;
        let weight = u16::parse(rdata, i)?;
        let port = u16::parse(rdata, i)?;
        let target = DnsName::parse(rdata, i)?;
        let parameters = Characters::parse(rdata, i)?;

        Ok(Self {
            priority,
            weight,
            port,
            target,
            parameters
        })
    }
}

impl<'a> WriteBytes for Svcb<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.priority.write(message)?;
        bytes += self.weight.write(message)?;
        bytes += self.port.write(message)?;
        bytes += self.target.write(message)?;
        bytes += self.parameters.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        15,
        [
            0x00, 0x0e, // priority
            0x00, 0x0e, // weight
            0x00, 0x0e, // port
            0x03, // length of "www"
            b'w', b'w', b'w', // "www"
            0x00, // end of name
            0x03, // length of "www"
            b'w', b'w', b'w', // "www"
        ],
        Svcb {
            priority: 14,
            weight: 14,
            port: 14,
            target: unsafe { DnsName::new_unchecked(b"\x03www\x00") },
            parameters: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
