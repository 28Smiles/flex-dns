#![no_main]

use libfuzzer_sys::fuzz_target;
use arrayvec::ArrayVec;
use flex_dns::{DnsMessage, DnsSection};

fuzz_target!(|data: &[u8]| {
    let mut buffer: ArrayVec<u8, 4096> = ArrayVec::new();
    // Copy the bytes
    buffer.try_extend_from_slice(data[..data.len().min(buffer.capacity())].as_ref()).unwrap();
    if let Ok(message) = DnsMessage::<16, { DnsSection::Questions }, _>::new(buffer) {
        let _ = message.header();
        if let Ok(header) = message.header() {
            let _ = header.id();
            let _ = header.kind();
            let _ = header.opcode();
            let _ = header.authoritative_answer();
            let _ = header.truncated();
            let _ = header.recursion_desired();
            let _ = header.recursion_available();
            let _ = header.response_code();
        }
        let mut questions = message.questions();
        if let Ok(iter) = questions.iter() {
            for question in iter {
                // Nothing
            }
        }
        let message = if let Ok(message) = questions.complete() {
            message
        } else {
            return;
        };
        let mut answers = message.answers();
        if let Ok(iter) = answers.iter() {
            for answer in iter {
                if let Ok(answer) = answer {
                    if let Ok(parsed) = answer.into_parsed() {
                        // Nothing
                    }
                }
            }
        }
        let message = if let Ok(message) = answers.complete() {
            message
        } else {
            return;
        };
        let mut name_servers = message.name_servers();
        if let Ok(iter) = name_servers.iter() {
            for name_server in iter {
                if let Ok(name_server) = name_server {
                    if let Ok(parsed) = name_server.into_parsed() {
                        // Nothing
                    }
                }
            }
        }
        let message = if let Ok(message) = name_servers.complete() {
            message
        } else {
            return;
        };
        let mut additionals = message.additionals();
        if let Ok(iter) = additionals.iter() {
            for additional in iter {
                if let Ok(additional) = additional {
                    if let Ok(parsed) = additional.into_parsed() {
                        // Nothing
                    }
                }
            }
        }
        let message = if let Ok(message) = additionals.complete() {
            message
        } else {
            return;
        };
    }
});
