use crate::{Buffer, DnsError, DnsMessage, DnsMessageError, MutBuffer};
use crate::characters::Characters;
use crate::parse::{Parse, ParseData};
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Address prefix list record
/// This record is used to store a list of address prefixes.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Apl<'a> {
    /// The address family for the prefix.
    pub address_family: u8,
    /// The prefix length.
    pub prefix: u8,
    /// The negation flag.
    pub negation: bool,
    /// The address family specific data.
    pub data: Characters<'a>,
}

impl<'a> RDataParse<'a> for Apl<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let bytes = rdata.parse_data();
        let address_family = u8::parse(rdata.buffer, i)?;
        let prefix = u8::parse(rdata.buffer, i)?;
        let length = u8::parse(rdata.buffer, i)?;
        let negation = length & 0x80 != 0;
        let length = length & 0x7F;

        if bytes.len() < *i + length as usize {
            return Err(DnsMessageError::DnsError(DnsError::UnexpectedEndOfBuffer));
        }

        let data = unsafe {
            Characters::new_unchecked(&rdata.buffer[*i - 1..*i + length as usize])
        };

        Ok(Self {
            address_family,
            prefix,
            negation,
            data,
        })
    }
}

impl<'a> WriteBytes for Apl<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.address_family.write(message)?;
        bytes += self.prefix.write(message)?;

        let mut length = self.data.as_ref().len() as u8;
        if self.negation {
            length |= 0x80;
        }

        bytes += length.write(message)?;
        bytes += message.write_bytes(self.data.as_ref())?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        6,
        [
            0x01, // address family
            0x02, // prefix
            0x03, // length
            0x01, 0x02, 0x03, // data
        ],
        Apl {
            address_family: 0x01,
            prefix: 0x02,
            negation: false,
            data: unsafe { Characters::new_unchecked(&[0x03, 0x01, 0x02, 0x03]) },
        }
    );
    parse_write_test!(
        6,
        [
            0x01, // address family
            0x02, // prefix
            0x83, // length
            0x01, 0x02, 0x03, // data
        ],
        Apl {
            address_family: 0x01,
            prefix: 0x02,
            negation: true,
            data: unsafe { Characters::new_unchecked(&[0x83, 0x01, 0x02, 0x03]) },
        },
        parse_negation,
        write_negation,
    );
}