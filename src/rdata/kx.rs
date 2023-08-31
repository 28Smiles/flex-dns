use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::name::DnsName;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Key exchange delegation record
/// This record describes a mechanism whereby authorization for one node
/// to act as a key exchange for another is delegated and made available
/// with the secure DNS protocol.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Kx<'a> {
    /// The preference given to this record among others at the same owner.
    pub preference: u16,
    /// The key exchange host name.
    pub exchange: DnsName<'a>,
}

impl<'a> RDataParse<'a> for Kx<'a> {
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

impl<'a> WriteBytes for Kx<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
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
        Kx {
            preference: 14,
            exchange: unsafe { DnsName::new_unchecked(b"\x03www\x00") },
        },
    );
}
