use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::name::DnsName;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Mail exchange
/// This record is used to specify the mail exchange for a domain name.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Mx<'a> {
    /// The preference of this mail exchange
    pub preference: u16,
    /// The domain name of the mail exchange
    pub exchange: DnsName<'a>,
}

impl<'a> RDataParse<'a> for Mx<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let preference = u16::parse(rdata.buffer, i)?;
        let exchange = DnsName::parse(rdata.buffer, i)?;

        Ok(Self {
            preference,
            exchange,
        })
    }
}

impl<'a> WriteBytes for Mx<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.preference.write(message)?;
        bytes += self.exchange.write(message)?;

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
            0x00, 0x0e, // preference
            0x03, b'w', b'w', b'w', 0x00, // exchange
        ],
        Mx {
            preference: 14,
            exchange: unsafe { DnsName::new_unchecked(b"\x03www\x00") },
        },
    );
}
