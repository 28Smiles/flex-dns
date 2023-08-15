use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::name::DnsName;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Service locator
/// This record is used to return a service location
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Srv<'a> {
    /// The priority of the target host
    pub priority: u16,
    /// The weight of the target host
    pub weight: u16,
    /// The port on the target host
    pub port: u16,
    /// The target host
    pub target: DnsName<'a>,
}

impl<'a> RDataParse<'a> for Srv<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let priority = u16::parse(rdata.buffer, i)?;
        let weight = u16::parse(rdata.buffer, i)?;
        let port = u16::parse(rdata.buffer, i)?;
        let target = DnsName::parse(rdata.buffer, i)?;

        Ok(Self {
            priority,
            weight,
            port,
            target,
        })
    }
}

impl<'a> WriteBytes for Srv<'a> {
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

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        11,
        [
            0x00, 0x0e, // priority
            0x00, 0x0e, // weight
            0x00, 0x0e, // port
            0x03,
            b'w', b'w', b'w',
            0x00, // target
        ],
        Srv {
            priority: 14,
            weight: 14,
            port: 14,
            target: unsafe { DnsName::new_unchecked(b"\x03www\x00") },
        },
    );
}
