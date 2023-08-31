#![no_std]
#![feature(generic_const_exprs)]

use crate::additional::DnsAdditionals;
use crate::answer::DnsAnswers;

use crate::header::DnsHeader;
use crate::name::DnsName;
use crate::name_servers::DnsNameServers;
use crate::parse::Parse;
use crate::question::DnsQuestions;

pub mod header;
pub mod name;
pub mod characters;
pub mod question;
pub mod name_servers;
pub mod additional;
pub mod answer;
pub mod rdata;
pub mod buffer;
mod parse;
mod write;

pub use buffer::{Buffer, MutBuffer};

#[derive(Debug, PartialEq)]
pub enum DnsMessageError {
    DnsError(DnsError),
    BufferError(BufferError),
}

impl From<DnsError> for DnsMessageError {
    fn from(e: DnsError) -> Self {
        DnsMessageError::DnsError(e)
    }
}

impl From<BufferError> for DnsMessageError {
    fn from(e: BufferError) -> Self {
        DnsMessageError::BufferError(e)
    }
}

#[derive(Debug, PartialEq)]
pub enum DnsError {
    MessageTooShort,
    InvalidHeader,
    InvalidQuestion,
    InvalidAnswer,
    InvalidAuthority,
    InvalidAdditional,
    PointerIntoTheFuture,
    PointerCycle,
    NameTooLong,
    LabelTooLong,
    CharacterStringTooLong,
    CharacterStringInvalidLength,
    RDataLongerThanMessage,
    UnexpectedEndOfBuffer,
    InvalidTxtRecord,
}

#[derive(Debug, PartialEq)]
pub enum BufferError {
    OutOfMemory,
    LengthOutOfBounds,
    InvalidLength,
    OffsetOutOfBounds,
}

const DNS_HEADER_SIZE: usize = 12;

/// A DNS message.
pub struct DnsMessage<
    const PTR_STORAGE: usize,
    const DNS_SECTION: usize,
    B,
> {
    buffer: B,
    position: usize,
    // Pointers are stored as offsets from the start of the buffer
    // We dont need this for reading, but we need it for writing compressed pointers
    ptr_storage: [usize; PTR_STORAGE],
    ptr_len: usize,
}

macro_rules! to_section_impl {
    ($from:expr, $to:expr) => {
        impl<
            const PTR_STORAGE: usize,
            B: Buffer,
        > DnsMessage<PTR_STORAGE, { $from }, B> {
            #[inline]
            pub fn next_section(self) -> DnsMessage<PTR_STORAGE, { $to }, B> {
                DnsMessage {
                    buffer: self.buffer,
                    position: self.position,
                    ptr_storage: self.ptr_storage,
                    ptr_len: self.ptr_len,
                }
            }
        }
    };
}

to_section_impl!(0, 1);
to_section_impl!(1, 2);
to_section_impl!(2, 3);

impl<
    const PTR_STORAGE: usize,
    const SECTION: usize,
    B: Buffer,
> DnsMessage<PTR_STORAGE, SECTION, B> {
    /// Creates a new DNS message with the given buffer.
    #[inline(always)]
    pub fn new(buffer: B) -> Result<Self, DnsMessageError> {
        if buffer.len() < DNS_HEADER_SIZE {
            return Err(DnsMessageError::DnsError(DnsError::MessageTooShort));
        }

        Ok(Self {
            buffer,
            position: DNS_HEADER_SIZE,
            ptr_storage: [0; PTR_STORAGE],
            ptr_len: 0,
        })
    }

    /// Resets the message to the start of the buffer.
    #[inline(always)]
    pub fn reset(self) -> DnsMessage<PTR_STORAGE, 0, B> {
        DnsMessage {
            buffer: self.buffer,
            position: 0,
            ptr_storage: self.ptr_storage,
            ptr_len: self.ptr_len,
        }
    }

    /// Aborts the message and returns the buffer.
    #[inline(always)]
    pub fn abort(self) -> Result<B, DnsMessageError> {
        Ok(self.buffer)
    }

    /// Returns the header of the message (read-only reference).
    #[inline(always)]
    pub fn header(&self) -> Result<&DnsHeader, DnsMessageError> {
        if self.buffer.len() < DNS_HEADER_SIZE {
            return Err(DnsMessageError::DnsError(DnsError::MessageTooShort));
        }

        Ok(DnsHeader::from_bytes(
            self.buffer.read_bytes_at(0, DNS_HEADER_SIZE)?
        ))
    }

    #[inline(always)]
    pub(crate) fn bytes_and_position(&mut self) -> (&[u8], &mut usize) {
        (self.buffer.bytes(), &mut self.position)
    }
}

impl<
    const PTR_STORAGE: usize,
    const SECTION: usize,
    B: MutBuffer + Buffer,
> DnsMessage<PTR_STORAGE, SECTION, B> {
    /// Creates a new DNS message with the given buffer.
    #[inline(always)]
    pub fn new_mut(mut buffer: B) -> Result<Self, DnsMessageError> {
        if buffer.len() < DNS_HEADER_SIZE {
            buffer.write_bytes(&[0; DNS_HEADER_SIZE])?;
        }

        Ok(Self {
            buffer,
            position: DNS_HEADER_SIZE,
            ptr_storage: [0; PTR_STORAGE],
            ptr_len: 0,
        })
    }

    /// Returns the header of the message as a mutable reference.
    #[inline(always)]
    pub fn header_mut(&mut self) -> Result<&mut DnsHeader, DnsMessageError> {
        self.position = core::cmp::max(self.position, DNS_HEADER_SIZE);
        Ok(DnsHeader::from_bytes_mut(
            self.buffer.read_bytes_at_mut(0, DNS_HEADER_SIZE)?
        ))
    }

    #[inline(always)]
    pub(crate) fn write_bytes(&mut self, bytes: &[u8]) -> Result<usize, DnsMessageError> {
        self.position += bytes.len();
        self.buffer.write_bytes(bytes)?;

        Ok(bytes.len())
    }

    #[inline(always)]
    pub(crate) fn truncate(&mut self) -> Result<(), DnsMessageError> {
        self.buffer.truncate(self.position)?;

        Ok(())
    }

    #[inline(always)]
    pub(crate) fn write_placeholder<const SIZE: usize>(&mut self) -> Result<impl Fn(&mut Self, [u8; SIZE]) -> usize, DnsMessageError> {
        let placeholder_pos = self.position;
        self.position += SIZE;
        self.buffer.write_bytes(&[0; SIZE])?;

        Ok(move |message: &mut DnsMessage<PTR_STORAGE, SECTION, B>, bytes: [u8; SIZE]| {
            message.buffer.write_array_at(placeholder_pos, bytes).unwrap();

            SIZE
        })
    }

    pub(crate) fn write_name(
        &mut self,
        name: DnsName,
    ) -> Result<usize, DnsMessageError> {
        // Try to find match
        for &idx in &self.ptr_storage[..self.ptr_len] {
            let mut i = idx;
            let name_at_idx = DnsName::parse(self.buffer.bytes(), &mut i)?;
            if name_at_idx == name {
                return Ok(self.write_bytes(&(idx as u16 | 0b1100_0000_0000_0000).to_be_bytes())?);
            }
        }

        // No match found, write name
        let (first, rest) = name.split_first()?;
        let original_position = self.position;
        let mut bytes_written = 0;
        bytes_written += self.write_bytes(&[first.len() as u8])?;
        bytes_written += self.write_bytes(first)?;

        if let Some(rest) = rest {
            bytes_written += self.write_name(rest)?;
        } else {
            bytes_written += self.write_bytes(&[0])?; // Null terminator
        }
        if self.ptr_len < PTR_STORAGE {
            // Store pointer for later, if we have space
            // If we dont have space, we just write the name uncompressed
            // in the future
            self.ptr_storage[self.ptr_len] = original_position;
            self.ptr_len += 1;
        }

        Ok(bytes_written)
    }
}

impl<
    const PTR_STORAGE: usize,
    B: Buffer,
> DnsMessage<PTR_STORAGE, 0, B> {
    /// Read or write questions in the message.
    #[inline(always)]
    pub fn questions(self) -> DnsQuestions<PTR_STORAGE, B> {
        DnsQuestions::new(self)
    }

    /// Completes and verifies the message and returns the buffer.
    #[inline(always)]
    pub fn complete(self) -> Result<(B, usize), DnsMessageError> {
        // Read the full packet.
        let questions = self.questions();
        let message = questions.complete()?;
        let answers = message.answers();
        let message = answers.complete()?;
        let name_servers = message.name_servers();
        let message = name_servers.complete()?;
        let additionals = message.additionals();
        let message = additionals.complete()?;

        Ok((message.buffer, message.position))
    }
}

impl<
    const PTR_STORAGE: usize,
    B: Buffer,
> DnsMessage<PTR_STORAGE, 1, B> {
    /// Read or write answers in the message.
    pub fn answers(self) -> DnsAnswers<PTR_STORAGE, B> {
        DnsAnswers::new(self)
    }

    /// Completes and verifies the message and returns the buffer.
    #[inline(always)]
    pub fn complete(self) -> Result<(B, usize), DnsMessageError> {
        // Read the full packet.
        let answers = self.answers();
        let message = answers.complete()?;
        let name_servers = message.name_servers();
        let message = name_servers.complete()?;
        let additionals = message.additionals();
        let message = additionals.complete()?;

        Ok((message.buffer, message.position))
    }
}

impl<
    const PTR_STORAGE: usize,
    B: Buffer,
> DnsMessage<PTR_STORAGE, 2, B> {
    /// Read or write name servers in the message.
    pub fn name_servers(self) -> DnsNameServers<PTR_STORAGE, B> {
        DnsNameServers::new(self)
    }

    /// Completes and verifies the message and returns the buffer.
    #[inline(always)]
    pub fn complete(self) -> Result<(B, usize), DnsMessageError> {
        // Read the full packet.
        let name_servers = self.name_servers();
        let message = name_servers.complete()?;
        let additionals = message.additionals();
        let message = additionals.complete()?;

        Ok((message.buffer, message.position))
    }
}

impl<
    const PTR_STORAGE: usize,
    B: Buffer,
> DnsMessage<PTR_STORAGE, 3, B> {
    /// Read or write additionals in the message.
    pub fn additionals(self) -> DnsAdditionals<PTR_STORAGE, B> {
        DnsAdditionals::new(self)
    }

    /// Completes and verifies the message and returns the buffer.
    #[inline(always)]
    pub fn complete(self) -> Result<(B, usize), DnsMessageError> {
        // Read the full packet.
        let additionals = self.additionals();
        let message = additionals.complete()?;

        Ok((message.buffer, message.position))
    }
}

#[cfg(any(feature = "heapless", feature = "arrayvec", feature = "vec"))]
#[cfg(test)]
mod test {
    use super::*;

    mod question {
        use crate::header::{DnsHeaderOpcode, DnsHeaderResponseCode};
        use crate::question::{DnsQClass, DnsQType, DnsQuestion};
        use super::*;

        #[cfg(feature = "heapless")]
        mod test_heapless {
            use heapless::Vec;
            use super::*;

            #[test]
            fn test_question_heapless() {
                test_question(Vec::<u8, 512>::new())
            }

            #[test]
            fn test_question_heapless_mut() {
                test_question(&mut Vec::<u8, 512>::new())
            }
        }

        #[cfg(feature = "arrayvec")]
        mod test_arrayvec {
            use arrayvec::ArrayVec;
            use super::*;

            #[test]
            fn test_question_arrayvec() {
                test_question(ArrayVec::<u8, 512>::new())
            }

            #[test]
            fn test_question_arrayvec_mut() {
                test_question(&mut ArrayVec::<u8, 512>::new())
            }


            #[test]
            fn query_google_com() {
                let buffer = ArrayVec::from([
                    0x00, 0x03, // ID
                    0x01, 0x00, // Flags
                    0x00, 0x01, // Question count
                    0x00, 0x00, // Answer count
                    0x00, 0x00, // Authority count
                    0x00, 0x00, // Additional count
                    0x06, b'g', b'o', b'o', b'g', b'l', b'e', // Name
                    0x03, b'c', b'o', b'm', // Name
                    0x00, // Name
                    0x00, 0x01, // Type
                    0x00, 0x01, // Class
                ]);
                let message: DnsMessage<8, 0, _> = DnsMessage::new(buffer).unwrap();
                assert_eq!(message.header().unwrap().id(), 0x0003);
                assert_eq!(message.header().unwrap().opcode(), DnsHeaderOpcode::Query);
                assert_eq!(message.header().unwrap().authoritative_answer(), false);
                assert_eq!(message.header().unwrap().truncated(), false);
                assert_eq!(message.header().unwrap().recursion_desired(), true);
                assert_eq!(message.header().unwrap().recursion_available(), false);
                assert_eq!(message.header().unwrap().response_code(), DnsHeaderResponseCode::NoError);
                let mut questions = message.questions();
                let mut question_iter = questions.iter().unwrap();
                let question = question_iter.next().unwrap().unwrap();
                assert_eq!(question.name, DnsName::new(b"\x06google\x03com\x00").unwrap());
                assert_eq!(question.qtype, DnsQType::A);
                assert_eq!(question.qclass, DnsQClass::IN);
                assert!(question_iter.next().is_none());
            }

            #[test]
            fn query_google_com_and_garbage() {
                let buffer = ArrayVec::from([
                    0x00, 0x03, // ID
                    0x01, 0x00, // Flags
                    0x00, 0x01, // Question count
                    0x00, 0x00, // Answer count
                    0x00, 0x00, // Authority count
                    0x00, 0x00, // Additional count
                    0x06, b'g', b'o', b'o', b'g', b'l', b'e', // Name
                    0x03, b'c', b'o', b'm', // Name
                    0x00, // Name
                    0x00, 0x01, // Type
                    0x00, 0x01, // Class
                    0x15, 0x16, 0x17, 0x18, // Garbage
                ]);
                let message: DnsMessage<8, 0, _> = DnsMessage::new(buffer).unwrap();
                assert_eq!(message.header().unwrap().id(), 0x0003);
                assert_eq!(message.header().unwrap().opcode(), DnsHeaderOpcode::Query);
                assert_eq!(message.header().unwrap().authoritative_answer(), false);
                assert_eq!(message.header().unwrap().truncated(), false);
                assert_eq!(message.header().unwrap().recursion_desired(), true);
                assert_eq!(message.header().unwrap().recursion_available(), false);
                assert_eq!(message.header().unwrap().response_code(), DnsHeaderResponseCode::NoError);
                let mut questions = message.questions();
                let mut question_iter = questions.iter().unwrap();
                let question = question_iter.next().unwrap().unwrap();
                assert_eq!(question.name, DnsName::new(b"\x06google\x03com\x00").unwrap());
                assert_eq!(question.qtype, DnsQType::A);
                assert_eq!(question.qclass, DnsQClass::IN);
                assert!(question_iter.next().is_none());
                let message = questions.complete().unwrap();
                let (buffer, pos) = message.complete().unwrap();
                assert_eq!(buffer[pos..], [0x15, 0x16, 0x17, 0x18]);
            }

            #[test]
            fn multiple_questions_compression() {
                let buffer: ArrayVec<u8, 512> = ArrayVec::new();
                let mut message: DnsMessage<8, 0, _> = DnsMessage::new_mut(buffer).unwrap();
                message.header_mut().unwrap().set_id(0x1234);
                message.header_mut().unwrap().set_opcode(DnsHeaderOpcode::Query);
                message.header_mut().unwrap().set_authoritative_answer(false);
                message.header_mut().unwrap().set_truncated(false);
                message.header_mut().unwrap().set_recursion_desired(false);
                message.header_mut().unwrap().set_recursion_available(false);
                message.header_mut().unwrap().set_response_code(DnsHeaderResponseCode::NoError);
                let mut questions = message.questions();
                questions.append(DnsQuestion {
                    name: DnsName::new(b"\x03www\x07example\x03com\x00").unwrap(),
                    qtype: DnsQType::A,
                    qclass: DnsQClass::IN,
                }).unwrap();
                questions.append(DnsQuestion {
                    name: DnsName::new(b"\x03www\x07example\x03com\x00").unwrap(),
                    qtype: DnsQType::AAAA,
                    qclass: DnsQClass::IN,
                }).unwrap();
                questions.append(DnsQuestion {
                    name: DnsName::new(b"\x03www\x07example\x03com\x00").unwrap(),
                    qtype: DnsQType::MX,
                    qclass: DnsQClass::IN,
                }).unwrap();
                questions.append(DnsQuestion {
                    name: DnsName::new(b"\x03www\x08examples\x03com\x00").unwrap(),
                    qtype: DnsQType::TXT,
                    qclass: DnsQClass::IN,
                }).unwrap();
                questions.append(DnsQuestion {
                    name: DnsName::new(b"\x08examples\x03com\x00").unwrap(),
                    qtype: DnsQType::CERT,
                    qclass: DnsQClass::IN,
                }).unwrap();
                let message = questions.complete().unwrap();
                let buffer = message.abort().unwrap();

                assert_eq!(
                    buffer.as_slice(),
                    [
                        0x12, 0x34, // ID
                        0b0000_0000, 0b0000_0000, // Flags
                        0x00, 0x05, // Question count
                        0x00, 0x00, // Answer count
                        0x00, 0x00, // Authority count
                        0x00, 0x00, // Additional count
                        0x03, b'w', b'w', b'w', // Name
                        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // Name
                        0x03, b'c', b'o', b'm', // Name
                        0x00, // Name
                        0x00, 0x01, // Type
                        0x00, 0x01, // Class
                        0xC0, 0x0C, // Name Pointer (0x0C = 12)
                        0x00, 0x1C, // Type
                        0x00, 0x01, // Class
                        0xC0, 0x0C, // Name Pointer (0x0C = 12)
                        0x00, 0x0F, // Type
                        0x00, 0x01, // Class
                        0x03, b'w', b'w', b'w', // Name
                        0x08, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b's', // Name
                        0xC0, 0x18, // Name Pointer (0x18 = 24)
                        0x00, 0x10, // Type
                        0x00, 0x01, // Class
                        0xC0, 0x31, // Name Pointer (0x31 = 48)
                        0x00, 0x25, // Type
                        0x00, 0x01, // Class
                    ].as_slice()
                );

                // Decode the message again and check that it is the same
                let message: DnsMessage<8, 0, _> = DnsMessage::new(buffer).unwrap();
                assert_eq!(message.header().unwrap().id(), 0x1234);
                assert_eq!(message.header().unwrap().opcode(), DnsHeaderOpcode::Query);
                assert_eq!(message.header().unwrap().authoritative_answer(), false);
                assert_eq!(message.header().unwrap().truncated(), false);
                assert_eq!(message.header().unwrap().recursion_desired(), false);
                assert_eq!(message.header().unwrap().recursion_available(), false);
                assert_eq!(message.header().unwrap().response_code(), DnsHeaderResponseCode::NoError);
                let mut questions = message.questions();
                let mut question_iter = questions.iter().unwrap();
                let question = question_iter.next().unwrap().unwrap();
                assert_eq!(question.name, DnsName::new(b"\x03www\x07example\x03com\x00").unwrap());
                assert_eq!(question.qtype, DnsQType::A);
                assert_eq!(question.qclass, DnsQClass::IN);
                let question = question_iter.next().unwrap().unwrap();
                assert_eq!(question.name, DnsName::new(b"\x03www\x07example\x03com\x00").unwrap());
                assert_eq!(question.qtype, DnsQType::AAAA);
                assert_eq!(question.qclass, DnsQClass::IN);
                let question = question_iter.next().unwrap().unwrap();
                assert_eq!(question.name, DnsName::new(b"\x03www\x07example\x03com\x00").unwrap());
                assert_eq!(question.qtype, DnsQType::MX);
                assert_eq!(question.qclass, DnsQClass::IN);
                let question = question_iter.next().unwrap().unwrap();
                assert_eq!(question.name, DnsName::new(b"\x03www\x08examples\x03com\x00").unwrap());
                assert_eq!(question.qtype, DnsQType::TXT);
                assert_eq!(question.qclass, DnsQClass::IN);
                let question = question_iter.next().unwrap().unwrap();
                assert_eq!(question.name, DnsName::new(b"\x08examples\x03com\x00").unwrap());
                assert_eq!(question.qtype, DnsQType::CERT);
                assert_eq!(question.qclass, DnsQClass::IN);
                assert!(question_iter.next().is_none());
            }
        }

        #[cfg(feature = "vec")]
        mod test_alloc {
            use alloc::vec::Vec;
            use super::*;

            extern crate alloc;

            #[test]
            fn test_question_vec() {
                test_question(Vec::<u8>::new())
            }

            #[test]
            fn test_question_vec_mut() {
                test_question(&mut Vec::<u8>::new())
            }
        }

        fn test_question<B: Buffer + MutBuffer>(buffer: B) {
            let mut message: DnsMessage<8, 0, _> = DnsMessage::new_mut(buffer).unwrap();
            message.header_mut().unwrap().set_id(0x1234);
            message.header_mut().unwrap().set_opcode(DnsHeaderOpcode::Query);
            message.header_mut().unwrap().set_authoritative_answer(false);
            message.header_mut().unwrap().set_truncated(false);
            message.header_mut().unwrap().set_recursion_desired(false);
            message.header_mut().unwrap().set_recursion_available(false);
            message.header_mut().unwrap().set_response_code(DnsHeaderResponseCode::NoError);
            let mut questions = message.questions();
            questions.append(DnsQuestion {
                name: DnsName::new(b"\x03www\x07example\x03com\x00").unwrap(),
                qtype: DnsQType::A,
                qclass: DnsQClass::IN,
            }).unwrap();
            let message = questions.complete().unwrap();
            let buffer = message.abort().unwrap();

            assert_eq!(buffer.bytes(), [
                0x12, 0x34, // ID
                0b0000_0000, 0b0000_0000, // Flags
                0x00, 0x01, // Question count
                0x00, 0x00, // Answer count
                0x00, 0x00, // Authority count
                0x00, 0x00, // Additional count
                0x03, b'w', b'w', b'w', // Name
                0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // Name
                0x03, b'c', b'o', b'm', // Name
                0x00, // Name
                0x00, 0x01, // Type
                0x00, 0x01, // Class
            ].as_slice());

            // Decode
            let message: DnsMessage<8, 0, _> = DnsMessage::new(buffer).unwrap();
            assert_eq!(message.header().unwrap().id(), 0x1234);
            assert_eq!(message.header().unwrap().opcode(), DnsHeaderOpcode::Query);
            assert_eq!(message.header().unwrap().authoritative_answer(), false);
            assert_eq!(message.header().unwrap().truncated(), false);
            assert_eq!(message.header().unwrap().recursion_desired(), false);
            assert_eq!(message.header().unwrap().recursion_available(), false);
            assert_eq!(message.header().unwrap().response_code(), DnsHeaderResponseCode::NoError);
            let mut questions = message.questions();
            let mut question_iter = questions.iter().unwrap();
            let question = question_iter.next().unwrap().unwrap();
            assert_eq!(question.name, DnsName::new(b"\x03www\x07example\x03com\x00").unwrap());
            assert_eq!(question.qtype, DnsQType::A);
            assert_eq!(question.qclass, DnsQClass::IN);
            assert!(question_iter.next().is_none());
        }
    }


    #[cfg(feature = "arrayvec")]
    mod answer {
        use arrayvec::ArrayVec;
        use crate::answer::{DnsAClass, DnsAnswer};
        use crate::header::{DnsHeaderOpcode, DnsHeaderResponseCode};
        use crate::rdata::{A, DnsAType};
        use super::*;

        #[test]
        fn single_answer() {
            let buffer: ArrayVec<u8, 512> = ArrayVec::new();
            let mut message: DnsMessage<8, 0, _> = DnsMessage::new_mut(buffer).unwrap();
            message.header_mut().unwrap().set_id(0x1234);
            message.header_mut().unwrap().set_opcode(DnsHeaderOpcode::Query);
            message.header_mut().unwrap().set_authoritative_answer(false);
            message.header_mut().unwrap().set_truncated(false);
            message.header_mut().unwrap().set_recursion_desired(false);
            message.header_mut().unwrap().set_recursion_available(false);
            message.header_mut().unwrap().set_response_code(DnsHeaderResponseCode::NoError);
            let message = message.questions().complete().unwrap();
            let message = {
                let mut answers = message.answers();
                answers.append(DnsAnswer {
                    name: DnsName::new(b"\x03www\x07example\x03com\x00").unwrap(),
                    aclass: DnsAClass::IN,
                    ttl: 0x12345678,
                    rdata: DnsAType::A(A { address: [127, 0, 0, 1] }),
                    cache_flush: false,
                }).unwrap();
                answers.complete().unwrap()
            };
            let buffer = message.abort().unwrap();

            assert_eq!(
                buffer.as_slice(),
                [
                    0x12, 0x34, // ID
                    0b0000_0000, 0b0000_0000, // Flags
                    0x00, 0x00, // Question count
                    0x00, 0x01, // Answer count
                    0x00, 0x00, // Authority count
                    0x00, 0x00, // Additional count
                    0x03, b'w', b'w', b'w', // Name
                    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // Name
                    0x03, b'c', b'o', b'm', // Name
                    0x00, // Name
                    0x00, 0x01, // Type
                    0x00, 0x01, // Class
                    0x12, 0x34, 0x56, 0x78, // TTL
                    0x00, 0x04, // Data length
                    127, 0, 0, 1, // Data
                ].as_slice()
            );

            // Decode the message again and check that it is the same
            let message: DnsMessage<8, 1, _> = DnsMessage::new(buffer).unwrap();
            assert_eq!(message.header().unwrap().id(), 0x1234);
            assert_eq!(message.header().unwrap().opcode(), DnsHeaderOpcode::Query);
            assert_eq!(message.header().unwrap().authoritative_answer(), false);
            assert_eq!(message.header().unwrap().truncated(), false);
            assert_eq!(message.header().unwrap().recursion_desired(), false);
            assert_eq!(message.header().unwrap().recursion_available(), false);
            assert_eq!(message.header().unwrap().response_code(), DnsHeaderResponseCode::NoError);
            let mut answers = message.answers();
            let mut answer_iter = answers.iter().unwrap();
            let answer = answer_iter.next().unwrap().unwrap();
            assert_eq!(answer.name, DnsName::new(b"\x03www\x07example\x03com\x00").unwrap());
            assert_eq!(answer.ttl, 0x12345678);
            assert_eq!(answer.into_parsed().unwrap().rdata, DnsAType::A(A { address: [127, 0, 0, 1] }));
            assert!(answer_iter.next().is_none());
        }
    }

    #[cfg(feature = "arrayvec")]
    mod error {
        use arrayvec::ArrayVec;
        use crate::header::{DnsHeaderOpcode, DnsHeaderResponseCode};
        use super::*;

        #[test]
        fn truncated() {
            let buffer: ArrayVec<u8, 12> = ArrayVec::from([
                0x12, 0x34, // ID
                0b0000_0000, 0b0000_0000, // Flags
                0x00, 0x01, // Question count
                0x00, 0x00, // Answer count
                0x00, 0x00, // Authority count
                0x00, 0x00, // Additional count
                // Premature end of message
            ]);
            let message: DnsMessage<8, 0, _> = DnsMessage::new(buffer).unwrap();
            assert_eq!(message.header().unwrap().id(), 0x1234);
            assert_eq!(message.header().unwrap().opcode(), DnsHeaderOpcode::Query);
            assert_eq!(message.header().unwrap().authoritative_answer(), false);
            assert_eq!(message.header().unwrap().truncated(), false);
            assert_eq!(message.header().unwrap().recursion_desired(), false);
            assert_eq!(message.header().unwrap().recursion_available(), false);
            assert_eq!(message.header().unwrap().response_code(), DnsHeaderResponseCode::NoError);
            let mut questions = message.questions();
            let mut question_iter = questions.iter().unwrap();
            assert_eq!(
                question_iter.next(),
                Some(Err(DnsMessageError::DnsError(DnsError::UnexpectedEndOfBuffer)))
            );
        }
    }
}
