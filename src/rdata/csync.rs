use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Child-to-Parent Synchronization (CSYNC) Record
/// This record type is used to publish the synchronization state of a child zone to its parent zone.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct CSync<'a> {
    /// serial is the serial number of the zone
    pub serial: u32,
    /// flags is a bitmap of flags (see [RFC 7477](https://tools.ietf.org/html/rfc7477))
    pub flags: u16,
    /// type_bit_maps is the set of RRset types present at the next owner name in the zone
    pub type_bit_maps: Characters<'a>,
}

impl<'a> RDataParse<'a> for CSync<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let serial = u32::parse(rdata, i)?;
        let flags = u16::parse(rdata, i)?;
        let type_bit_maps = Characters::parse(rdata, i)?;

        Ok(Self {
            serial,
            flags,
            type_bit_maps
        })
    }
}

impl<'a> WriteBytes for CSync<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.serial.write(message)?;
        bytes += self.flags.write(message)?;
        bytes += self.type_bit_maps.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        10,
        [
            0x00, 0x01, 0x02, 0x03, // serial
            0x10, 0x01, // flags
            3, b'w', b'w', b'w', // type_bit_maps
        ],
        CSync {
            serial: 0x00010203,
            flags: 0x1001,
            type_bit_maps: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
