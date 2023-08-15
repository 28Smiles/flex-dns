use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::name::DnsName;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # A domain name pointer
/// This record is used to return a canonical name for an alias
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Ptr<'a> {
    /// The canonical name for the alias
    pub name: DnsName<'a>,
}

impl<'a> RDataParse<'a> for Ptr<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let name = DnsName::parse(rdata.buffer, i)?;

        Ok(Self {
            name,
        })
    }
}

impl<'a> WriteBytes for Ptr<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        self.name.write(message)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        17,
        [
            0x03, b'w', b'w', b'w',
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
        ],
        Ptr {
            name: unsafe { DnsName::new_unchecked(b"\x03www\x07example\x03com\x00") },
        },
    );
}
