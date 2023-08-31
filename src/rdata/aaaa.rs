use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # IPv6 address record
/// This record is used to return a IPv6 address for a host.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Aaaa {
    /// IPv6 address
    pub address: [u8; 16],
}

impl<'a> RDataParse<'a> for Aaaa {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        Ok(Self { address: <[u8; 16]>::parse(rdata.buffer, i)? })
    }
}

impl WriteBytes for Aaaa {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        self.address.write(message)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        16,
        [
            0x01, 0x02, 0x03, 0x04,
            0x01, 0x02, 0x03, 0x04,
            0x01, 0x02, 0x03, 0x04,
            0x01, 0x02, 0x03, 0x04,
        ],
        Aaaa {
            address: [
                0x01, 0x02, 0x03, 0x04,
                0x01, 0x02, 0x03, 0x04,
                0x01, 0x02, 0x03, 0x04,
                0x01, 0x02, 0x03, 0x04,
            ],
        },
    );
}