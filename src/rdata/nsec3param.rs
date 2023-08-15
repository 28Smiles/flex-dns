use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Next secure record version 3 parameters
/// This record is used to provide parameters for the NSEC3 records.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Nsec3Param<'a> {
    /// Hash algorithm
    pub hash_algorithm: u8,
    /// Flags
    pub flags: u8,
    /// Iterations
    pub iterations: u16,
    /// Salt
    pub salt: Characters<'a>,
}

impl<'a> RDataParse<'a> for Nsec3Param<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let hash_algorithm = u8::parse(rdata, i)?;
        let flags = u8::parse(rdata, i)?;
        let iterations = u16::parse(rdata, i)?;
        let salt = Characters::parse(rdata, i)?;

        Ok(Self {
            hash_algorithm,
            flags,
            iterations,
            salt,
        })
    }
}

impl<'a> WriteBytes for Nsec3Param<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.hash_algorithm.write(message)?;
        bytes += self.flags.write(message)?;
        bytes += self.iterations.write(message)?;
        bytes += self.salt.write(message)?;

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
            0x0e, // hash algorithm
            0xae, // flags
            0x0a, 0xfe, // iterations
            0x03, b'w', b'w', b'w', // salt
        ],
        Nsec3Param {
            hash_algorithm: 0x0e,
            flags: 0xae,
            iterations: 0x0afe,
            salt: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
