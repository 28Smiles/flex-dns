use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # DNSSEC trust authorities record (TA)
/// This record is used to publish the public key of a DNSSEC trust anchor.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Ta<'a> {
    /// trust_anchor_link is the trust anchor link
    pub trust_anchor_link: Characters<'a>,
}

impl<'a> RDataParse<'a> for Ta<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let trust_anchor_link = Characters::parse(rdata, i)?;

        Ok(Self {
            trust_anchor_link,
        })
    }
}

impl<'a> WriteBytes for Ta<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        self.trust_anchor_link.write(message)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        4,
        [
            0x03,
            b'w', b'w', b'w', // trust_anchor_link
        ],
        Ta {
            trust_anchor_link: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
