use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # MAC address record (EUI-64)
/// This record is used to translate between a 64-bit MAC address used by the
/// IEEE 802 protocol family and a fully qualified domain name.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct EUI64 {
    /// mac_address is the MAC address
    pub mac_address: [u8; 8],
}

impl<'a> RDataParse<'a> for EUI64 {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let mac_address = <[u8; 8]>::parse(rdata, i)?;

        Ok(Self {
            mac_address,
        })
    }
}

impl<'a> WriteBytes for EUI64 {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        self.mac_address.write(message)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        8,
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ],
        EUI64 {
            mac_address: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
            ],
        },
    );
}
