use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Host information
/// This record is used to return host information
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct HInfo<'a> {
    /// The CPU type
    pub cpu: Characters<'a>,
    /// The OS type
    pub os: Characters<'a>,
}

impl<'a> RDataParse<'a> for HInfo<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let cpu = Characters::parse(rdata, i)?;
        let os = Characters::parse(rdata, i)?;

        Ok(Self {
            cpu,
            os,
        })
    }
}

impl<'a> WriteBytes for HInfo<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.cpu.write(message)?;
        bytes += self.os.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        8,
        [
            3, b'w', b'w', b'w',
            3, b'c', b'o', b'm',
        ],
        HInfo {
            cpu: unsafe { Characters::new_unchecked(b"www") },
            os: unsafe { Characters::new_unchecked(b"com") },
        },
    );
}
