use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Location information
/// This record is used to return a location for a host
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Loc {
    /// The version of the location record
    pub version: u8,
    /// The size of the location record
    pub size: u8,
    /// The horizontal precision of the location record
    pub horizontal_precision: u8,
    /// The vertical precision of the location record
    pub vertical_precision: u8,
    /// The latitude of the location record
    pub latitude: u32,
    /// The longitude of the location record
    pub longitude: u32,
    /// The altitude of the location record
    pub altitude: u32,
}

impl<'a> RDataParse<'a> for Loc {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let version = u8::parse(rdata.buffer, i)?;
        let size = u8::parse(rdata.buffer, i)?;
        let horizontal_precision = u8::parse(rdata.buffer, i)?;
        let vertical_precision = u8::parse(rdata.buffer, i)?;
        let latitude = u32::parse(rdata.buffer, i)?;
        let longitude = u32::parse(rdata.buffer, i)?;
        let altitude = u32::parse(rdata.buffer, i)?;

        Ok(Self {
            version,
            size,
            horizontal_precision,
            vertical_precision,
            latitude,
            longitude,
            altitude,
        })
    }
}

impl WriteBytes for Loc {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.version.write(message)?;
        bytes += self.size.write(message)?;
        bytes += self.horizontal_precision.write(message)?;
        bytes += self.vertical_precision.write(message)?;
        bytes += self.latitude.write(message)?;
        bytes += self.longitude.write(message)?;
        bytes += self.altitude.write(message)?;

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
            0x0e, // version
            0x0d, // size
            0x0c, // horizontal precision
            0x0b, // vertical precision
            0x00, 0x00, 0x00, 0x0a, // latitude
            0x00, 0x00, 0x00, 0x0b, // longitude
            0x00, 0x00, 0x00, 0x0c, // altitude
        ],
        Loc {
            version: 0x0e,
            size: 0x0d,
            horizontal_precision: 0x0c,
            vertical_precision: 0x0b,
            latitude: 0x0a,
            longitude: 0x0b,
            altitude: 0x0c,
        },
    );
}
