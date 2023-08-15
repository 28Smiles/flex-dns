use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Next secure record version 3
/// This record is used to provide authenticated denial of existence for DNSSEC.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Nsec3<'a> {
    /// The hash algorithm used to hash the original owner name field.
    pub hash_algorithm: u8,
    /// The flags field.
    pub flags: u8,
    /// The number of iterations used to construct the hash.
    pub iterations: u16,
    /// The salt used to construct the hash.
    pub salt: Characters<'a>,
    /// The next hashed owner name in the canonical ordering of the zone.
    pub next_hashed_owner_name: Characters<'a>,
    /// The type bit maps field.
    pub type_bit_maps: Characters<'a>,
}

impl<'a> RDataParse<'a> for Nsec3<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let hash_algorithm = u8::parse(rdata, i)?;
        let flags = u8::parse(rdata, i)?;
        let iterations = u16::parse(rdata, i)?;
        let salt = Characters::parse(rdata, i)?;
        let next_hashed_owner_name = Characters::parse(rdata, i)?;
        let type_bit_maps = Characters::parse(rdata, i)?;

        Ok(Self {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner_name,
            type_bit_maps,
        })
    }
}

impl<'a> WriteBytes for Nsec3<'a> {
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
        bytes += self.next_hashed_owner_name.write(message)?;
        bytes += self.type_bit_maps.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        16,
        [
            0x0e, // hash algorithm
            0x0a, // flags
            0x00, 0x0e, // iterations
            0x03, // length of salt
            b'a', b'b', b'c',
            0x03, // length of next hashed owner name
            b'd', b'e', b'f',
            0x03, // length of type bit maps
            b'w', b'w', b'w',
        ],
        Nsec3 {
            hash_algorithm: 0x0e,
            flags: 0x0a,
            iterations: 0x000e,
            salt: unsafe { Characters::new_unchecked(b"abc") },
            next_hashed_owner_name: unsafe { Characters::new_unchecked(b"def") },
            type_bit_maps: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
