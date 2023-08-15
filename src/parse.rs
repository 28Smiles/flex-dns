use crate::{DnsError, DnsMessageError};

pub(crate) trait ParseData<'a> {
    fn parse_data(&self) -> &'a [u8];
}

impl<'a> ParseData<'a> for &'a [u8] {
    #[inline(always)]
    fn parse_data(&self) -> &'a [u8] {
        *self
    }
}

pub(crate) trait Parse<'a>: Sized {
    fn parse<T: ParseData<'a>>(bytes: T, i: &mut usize) -> Result<Self, DnsMessageError>;
}

impl<'a, S: ParseBytes<'a>> Parse<'a> for S {
    #[inline(always)]
    fn parse<T: ParseData<'a>>(bytes: T, i: &mut usize) -> Result<Self, DnsMessageError> {
        Self::parse_bytes(bytes.parse_data(), i)
    }
}

pub(crate) trait ParseBytes<'a>: Sized {
    fn parse_bytes(bytes: &'a [u8], i: &mut usize) -> Result<Self, DnsMessageError>;
}

impl<'a> ParseBytes<'a> for u8 {
    #[inline]
    fn parse_bytes(bytes: &'a [u8], i: &mut usize) -> Result<Self, DnsMessageError> {
        if bytes.len() < *i + 1 {
            return Err(DnsMessageError::DnsError(DnsError::UnexpectedEndOfBuffer));
        }

        let value = bytes[*i];
        *i += 1;

        Ok(value)
    }
}

impl<'a> ParseBytes<'a> for u16 {
    #[inline]
    fn parse_bytes(bytes: &'a [u8], i: &mut usize) -> Result<Self, DnsMessageError> {
        if bytes.len() < *i + 2 {
            return Err(DnsMessageError::DnsError(DnsError::UnexpectedEndOfBuffer));
        }

        let value = u16::from_be_bytes([
            bytes[*i],
            bytes[*i + 1]
        ]);
        *i += 2;

        Ok(value)
    }
}

impl<'a> ParseBytes<'a> for u32 {
    #[inline]
    fn parse_bytes(bytes: &'a [u8], i: &mut usize) -> Result<Self, DnsMessageError> {
        if bytes.len() < *i + 4 {
            return Err(DnsMessageError::DnsError(DnsError::UnexpectedEndOfBuffer));
        }

        let value = u32::from_be_bytes([
            bytes[*i],
            bytes[*i + 1],
            bytes[*i + 2],
            bytes[*i + 3]
        ]);
        *i += 4;

        Ok(value)
    }
}

impl<'a> ParseBytes<'a> for u64 {
    #[inline]
    fn parse_bytes(bytes: &'a [u8], i: &mut usize) -> Result<Self, DnsMessageError> {
        if bytes.len() < *i + 8 {
            return Err(DnsMessageError::DnsError(DnsError::UnexpectedEndOfBuffer));
        }

        let value = u64::from_be_bytes([
            bytes[*i],
            bytes[*i + 1],
            bytes[*i + 2],
            bytes[*i + 3],
            bytes[*i + 4],
            bytes[*i + 5],
            bytes[*i + 6],
            bytes[*i + 7]
        ]);
        *i += 8;

        Ok(value)
    }
}

impl<'a, const SIZE: usize> ParseBytes<'a> for [u8; SIZE] {
    #[inline]
    fn parse_bytes(bytes: &'a [u8], i: &mut usize) -> Result<Self, DnsMessageError> {
        if bytes.len() < *i + SIZE {
            return Err(DnsMessageError::DnsError(DnsError::UnexpectedEndOfBuffer));
        }

        let mut value = [0u8; SIZE];
        value.copy_from_slice(&bytes[*i..*i + SIZE]);
        *i += SIZE;

        Ok(value)
    }
}
