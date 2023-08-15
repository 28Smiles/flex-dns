use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::name::DnsName;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # The canonical name for an alias
/// This record is used to return a canonical name for an alias
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct CName<'a> {
    /// The canonical name for the alias
    pub name: DnsName<'a>,
}

impl<'a> RDataParse<'a> for CName<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        Ok(Self {
            name: DnsName::parse(rdata.buffer, i)?,
        })
    }
}

impl<'a> WriteBytes for CName<'a> {
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
        14,
        [
            3, b'w', b'w', b'w',
            4, b't', b'e', b's', b't',
            3, b'c', b'o', b'm',
            0
        ],
        CName {
            name: unsafe { DnsName::new_unchecked(b"\x03www\x04test\x03com\x00") },
        },
    );
}
