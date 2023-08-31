use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::answer::DnsAClass;
use crate::name::DnsName;
use crate::parse::{Parse, ParseBytes};
use crate::question::DnsQType;
use crate::rdata::{DnsAType, RData};
use crate::write::WriteBytes;

/// A DNS message additionals section.
pub struct DnsAdditionals<
    const PTR_STORAGE: usize,
    B: Buffer,
> {
    message: DnsMessage<PTR_STORAGE, 3, B>,
    remaining: usize,
}

impl<
    const PTR_STORAGE: usize,
    B: Buffer,
> DnsAdditionals<PTR_STORAGE, B> {
    #[inline(always)]
    pub(crate) fn new(message: DnsMessage<PTR_STORAGE, 3, B>) -> Self {
        let remaining = message.header().unwrap().answer_count() as usize;
        Self {
            message,
            remaining,
        }
    }

    /// Return an iterator over the additionals section.
    #[inline(always)]
    pub fn iter(&mut self) -> Result<DnsAdditionalsIterator, DnsMessageError> {
        let (bytes, position) = self.message.bytes_and_position();

        Ok(DnsAdditionalsIterator {
            buffer: bytes,
            current_position: position,
            remaining: &mut self.remaining,
        })
    }

    /// Complete writing to the additionals section and return the message.
    #[inline(always)]
    pub fn complete(mut self) -> Result<DnsMessage<PTR_STORAGE, 3, B>, DnsMessageError> {
        if self.remaining != 0 {
            for x in self.iter()? { x?; }
        }

        Ok(DnsMessage {
            buffer: self.message.buffer,
            position: self.message.position,
            ptr_storage: self.message.ptr_storage,
            ptr_len: self.message.ptr_len,
        })
    }
}

impl<
    const PTR_STORAGE: usize,
    B: MutBuffer + Buffer,
> DnsAdditionals<PTR_STORAGE, B> {
    /// Append an additional to the message. This will overwrite the next
    /// additional or further sections, if any.
    pub fn append(&mut self, answer: DnsAdditional<DnsAType>) -> Result<(), DnsMessageError> {
        // Truncate the buffer to the current position.
        self.message.truncate()?;
        answer.write(&mut self.message)?;
        // Set answer_count in the header to the current answer count + 1.
        let answer_count = self.message.header().unwrap().answer_count();
        let answer_count = answer_count + 1 - self.remaining as u16;
        self.message.header_mut()?.set_answer_count(answer_count);
        self.message.header_mut()?.set_name_server_count(0);
        self.message.header_mut()?.set_additional_records_count(0);
        self.remaining = 0;

        Ok(())
    }
}

/// An iterator over the additionals section of a DNS message.
pub struct DnsAdditionalsIterator<'a> {
    buffer: &'a [u8],
    current_position: &'a mut usize,
    remaining: &'a mut usize,
}

impl<'a> Iterator for DnsAdditionalsIterator<'a> {
    type Item = Result<DnsAdditional<'a, RData<'a>>, DnsMessageError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if *self.remaining == 0 {
            return None;
        }

        let additional = DnsAdditional::parse(
            self.buffer, self.current_position
        );
        *self.remaining -= 1;

        Some(additional)
    }
}

/// A DNS message additional.
#[derive(Debug, PartialEq)]
pub struct DnsAdditional<'a, D> {
    /// The name of the additional.
    pub name: DnsName<'a>,
    /// The data of the additional.
    pub rdata: D,
    /// Whether the additional should be cached.
    pub cache_flush: bool,
    /// The class of the additional.
    pub aclass: DnsAClass,
    /// The time to live of the additional.
    pub ttl: u32,
}

impl<'a> DnsAdditional<'a, RData<'a>> {
    /// Parse the rdata of the additional into a structured type.
    #[inline(always)]
    pub fn into_parsed(self) -> Result<DnsAdditional<'a, DnsAType<'a>>, DnsMessageError> {
        Ok(DnsAdditional {
            name: self.name,
            rdata: self.rdata.into_parsed()?,
            cache_flush: self.cache_flush,
            aclass: self.aclass,
            ttl: self.ttl,
        })
    }
}

impl<'a> ParseBytes<'a> for DnsAdditional<'a, RData<'a>> {
    fn parse_bytes(bytes: &'a [u8], i: &mut usize) -> Result<Self, DnsMessageError> {
        let name = DnsName::parse(bytes, i)?;
        let atype_id = u16::parse(bytes, i)?;
        let atype = DnsQType::from_id(atype_id);
        let cache_flush = atype_id & 0b1000_0000_0000_0000 != 0;
        let aclass = DnsAClass::from_id(u16::parse(bytes, i)?);
        let ttl = u32::parse(bytes, i)?;
        let rdata = RData::parse(bytes, i, atype)?;

        Ok(Self {
            name,
            rdata,
            cache_flush,
            aclass,
            ttl,
        })
    }
}

impl<'a> WriteBytes for DnsAdditional<'a, DnsAType<'a>> {
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;
        // Write the name to the buffer using the pointer storage for compression.
        bytes += self.name.write(message)?;
        // Write the atype and aclass to the buffer.
        bytes += self.rdata.id().write(message)?;
        let mut aclass = self.aclass.id();
        if self.cache_flush {
            aclass |= 0b1000_0000;
        }
        bytes += aclass.write(message)?;
        // Write the ttl to the buffer.
        bytes += self.ttl.write(message)?;
        let rdata_len_placeholder = message.write_placeholder::<2>()?;
        // Write the type specific data to the buffer.
        let rdata_len = self.rdata.write(message)?;
        bytes += rdata_len;
        bytes += rdata_len_placeholder(message, (rdata_len as u16).to_be_bytes());

        Ok(bytes)
    }
}
