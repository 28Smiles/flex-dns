# Flex-Dns

[![Crates](https://badgen.net/crates/v/flex-dns)](https://crates.io/crates/flex-dns)
[![docs.rs](https://docs.rs/flex-dns/badge.svg)](https://docs.rs/flex-dns)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/28Smiles/flex-dns/actions/workflows/rust.yml/badge.svg)](https://github.com/28Smiles/flex-dns/actions/workflows/rust.yml)
[![codecov](https://codecov.io/gh/28Smiles/flex-dns/graph/badge.svg?token=Lf3vnP2U5z)](https://codecov.io/gh/28Smiles/flex-dns)

Flex-Dns is a DNS parser and serializer written in Rust. It is designed to be used in embedded systems, 
but can also be used in other projects. For usage in embedded systems, we completely avoid the usage of the
heap. This means that the library is `no_std` compatible. This library is runtime panic free, and all errors
are handled by returning a `Result` type, this is ensured by fuzzing the library. If you are missing a feature
or find a bug, feel free to open an issue or a pull request.
