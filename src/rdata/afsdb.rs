use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::name::DnsName;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # AFS data base location
/// This record is used to locate a server that has a copy of the named AFS cell's database.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct AfsDb<'a> {
    /// The subtype of the record
    pub subtype: u16,
    /// The hostname of the server
    pub hostname: DnsName<'a>,
}

impl<'a> RDataParse<'a> for AfsDb<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let subtype = u16::parse(rdata.buffer, i)?;
        let hostname = DnsName::parse(rdata.buffer, i)?;

        Ok(Self {
            subtype,
            hostname,
        })
    }
}

impl<'a> WriteBytes for AfsDb<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.subtype.write(message)?;
        bytes += self.hostname.write(message)?;

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
            0x00, 0x01, // subtype
            0x03, b'f', b'o', b'o', 0x01, b'b', // hostname
            0x00, // null terminator
        ],
        AfsDb {
            subtype: 1,
            hostname: unsafe { DnsName::new_unchecked(b"\x03foo\x01b\x00") },
        },
    );
}