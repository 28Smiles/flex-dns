use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::characters::Characters;
use crate::name::DnsName;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Naming authority pointer
/// This record is used to delegate a DNS zone to use the given authoritative name servers
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Naptr<'a> {
    /// The order in which the NAPTR records MUST be processed in order to accurately represent the ordered list of Rules.
    pub order: u16,
    /// The preference value of this NAPTR record.
    pub preference: u16,
    /// The flags field specifies various flags that control the processing of the NAPTR record.
    pub flags: Characters<'a>,
    /// The service field specifies the service(s) available down this rewrite path.
    pub service: Characters<'a>,
    /// The regexp field specifies a substitution expression that is applied to the original string held by the client in order to construct the next domain name to lookup.
    pub regexp: Characters<'a>,
    /// The replacement field specifies the next domain-name to query for NAPTR, SRV, or Address records depending on the value of the flags field.
    pub replacement: DnsName<'a>,
}

impl<'a> RDataParse<'a> for Naptr<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let order = u16::parse(rdata.buffer, i)?;
        let preference = u16::parse(rdata.buffer, i)?;
        let flags = Characters::parse(rdata.buffer, i)?;
        let service = Characters::parse(rdata.buffer, i)?;
        let regexp = Characters::parse(rdata.buffer, i)?;
        let replacement = DnsName::parse(rdata.buffer, i)?;

        Ok(Self {
            order,
            preference,
            flags,
            service,
            regexp,
            replacement,
        })
    }
}

impl<'a> WriteBytes for Naptr<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.order.write(message)?;
        bytes += self.preference.write(message)?;
        bytes += self.flags.write(message)?;
        bytes += self.service.write(message)?;
        bytes += self.regexp.write(message)?;
        bytes += self.replacement.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        21,
        [
            0x00, 0x0e, // order
            0x00, 0x0f, // preference
            0x03, b'a', b'b', b'c', // flags
            0x03, b'd', b'e', b'f', // service
            0x03, b'g', b'h', b'i', // regexp
            0x03, b'j', b'k', b'l', 0x00, // replacement
        ],
        Naptr {
            order: 14,
            preference: 15,
            flags: unsafe { Characters::new_unchecked(b"abc") },
            service: unsafe { Characters::new_unchecked(b"def") },
            regexp: unsafe { Characters::new_unchecked(b"ghi") },
            replacement: unsafe { DnsName::new_unchecked(b"\x03jkl\x00") },
        },
    );
}
