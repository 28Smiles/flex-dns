use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # MAC address record (EUI-48)
/// This record is used to translate between a 48-bit MAC address used by the
/// IEEE 802 protocol family and a fully qualified domain name.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct EUI48 {
    /// mac_address is the MAC address
    pub mac_address: [u8; 6],
}

impl<'a> RDataParse<'a> for EUI48 {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let mac_address = <[u8; 6]>::parse(rdata, i)?;

        Ok(Self {
            mac_address,
        })
    }
}

impl<'a> WriteBytes for EUI48 {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        self.mac_address.write(message)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        6,
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06
        ],
        EUI48 {
            mac_address: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
        },
    );
}
