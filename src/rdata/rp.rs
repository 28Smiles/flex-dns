use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::name::DnsName;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Responsible person
/// This record is used to identify the responsible person for a domain
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Rp<'a> {
    /// The mailbox name of the responsible person
    pub mbox: DnsName<'a>,
    /// The domain name of the responsible person
    pub txt: DnsName<'a>,
}

impl<'a> RDataParse<'a> for Rp<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let mbox = DnsName::parse(rdata.buffer, i)?;
        let txt = DnsName::parse(rdata.buffer, i)?;

        Ok(Self {
            mbox,
            txt,
        })
    }
}

impl<'a> WriteBytes for Rp<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;
        bytes += self.mbox.write(message)?;
        bytes += self.txt.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        33,
        [
            0x03, b'w', b'w', b'w',
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // mbox
            0x03, b'w', b'w', b'w',
            0x06, b'g', b'o', b'o', b'g', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // txt
        ],
        Rp {
            mbox: unsafe { DnsName::new_unchecked(b"\x03www\x07example\x03com\x00") },
            txt: unsafe { DnsName::new_unchecked(b"\x03www\x06google\x03com\x00") },
        },
    );
}
