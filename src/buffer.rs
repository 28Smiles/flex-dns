use crate::BufferError;

pub trait Buffer {
    /// The whole buffer as a slice.
    fn bytes(&self) -> &[u8];

    /// The length of the data in the buffer.
    fn len(&self) -> usize;

    /// Reads a given number of bytes at the given offset.
    fn read_bytes_at(&self, offset: usize, length: usize) -> Result<&[u8], BufferError>;
}

pub trait MutBuffer {
    /// Truncates the buffer to the given length.
    fn truncate(&mut self, new_len: usize) -> Result<(), BufferError>;

    /// Writes the given data at the given offset.
    fn write_array_at<const BYTES: usize>(&mut self, offset: usize, data: [u8; BYTES]) -> Result<(), BufferError>;

    /// Writes the given data at the end of the buffer.
    fn write_bytes(&mut self, data: &[u8]) -> Result<(), BufferError>;

    /// Writes the given data at the end of the buffer.
    fn write_array<const BYTES: usize>(&mut self, data: [u8; BYTES]) -> Result<(), BufferError>;

    /// Reads a given number of bytes at the given offset.
    fn read_bytes_at_mut(&mut self, offset: usize, length: usize) -> Result<&mut [u8], BufferError>;
}

impl<T: Buffer> Buffer for &'_ T {
    fn bytes(&self) -> &[u8] {
        (*self).bytes()
    }

    fn len(&self) -> usize {
        (*self).len()
    }

    fn read_bytes_at(&self, offset: usize, length: usize) -> Result<&[u8], BufferError> {
        (*self).read_bytes_at(offset, length)
    }
}

impl<T: Buffer> Buffer for &'_ mut T {
    fn bytes(&self) -> &[u8] {
        <T as Buffer>::bytes(*self)
    }

    fn len(&self) -> usize {
        <T as Buffer>::len(*self)
    }

    fn read_bytes_at(&self, offset: usize, length: usize) -> Result<&[u8], BufferError> {
        <T as Buffer>::read_bytes_at(*self, offset, length)
    }
}

impl<T: MutBuffer + Buffer> MutBuffer for &'_ mut T {
    fn truncate(&mut self, new_len: usize) -> Result<(), BufferError> {
        (*self).truncate(new_len)
    }

    fn write_array_at<const BYTES: usize>(&mut self, offset: usize, data: [u8; BYTES]) -> Result<(), BufferError> {
        (*self).write_array_at(offset, data)
    }

    fn write_bytes(&mut self, data: &[u8]) -> Result<(), BufferError> {
        (*self).write_bytes(data)
    }

    fn write_array<const BYTES: usize>(&mut self, data: [u8; BYTES]) -> Result<(), BufferError> {
        (*self).write_array(data)
    }

    fn read_bytes_at_mut(&mut self, offset: usize, length: usize) -> Result<&mut [u8], BufferError> {
        (*self).read_bytes_at_mut(offset, length)
    }
}

#[cfg(any(feature = "heapless", feature = "arrayvec", feature = "vec"))]
#[inline(always)]
fn check_length<const SIZE: usize>(offset: usize, length: usize) -> Result<(), BufferError> {
    if offset + length > SIZE {
        if offset > SIZE {
            return Err(BufferError::OffsetOutOfBounds);
        }
        return Err(BufferError::LengthOutOfBounds);
    }

    Ok(())
}

impl Buffer for &'_ [u8] {
    #[inline(always)]
    fn bytes(&self) -> &[u8] {
        self
    }

    #[inline(always)]
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    #[inline(always)]
    fn read_bytes_at(&self, offset: usize, length: usize) -> Result<&[u8], BufferError> {
        if offset + length > self.len() {
            if offset > self.len() {
                return Err(BufferError::OffsetOutOfBounds);
            }
            return Err(BufferError::LengthOutOfBounds);
        }

        Ok(&self[offset..offset + length])
    }
}

#[cfg(feature = "arrayvec")]
mod impl_arrayvec {
    use super::*;

    impl<const SIZE: usize> Buffer for arrayvec::ArrayVec<u8, SIZE> {
        #[inline(always)]
        fn bytes(&self) -> &[u8] {
            self.as_slice()
        }

        #[inline(always)]
        fn len(&self) -> usize {
            arrayvec::ArrayVec::len(self)
        }

        #[inline(always)]
        fn read_bytes_at(&self, offset: usize, length: usize) -> Result<&[u8], BufferError> {
            if offset + length > self.len() {
                if offset > self.len() {
                    return Err(BufferError::OffsetOutOfBounds);
                }
                return Err(BufferError::LengthOutOfBounds);
            }

            Ok(&self.as_slice()[offset..offset + length])
        }
    }

    impl<const SIZE: usize> MutBuffer for arrayvec::ArrayVec<u8, SIZE> {
        #[inline(always)]
        fn truncate(&mut self, new_len: usize) -> Result<(), BufferError> {
            if new_len > self.len() {
                return Err(BufferError::InvalidLength);
            }

            arrayvec::ArrayVec::truncate(self, new_len);
            Ok(())
        }

        #[inline(always)]
        fn write_array_at<const BYTES: usize>(&mut self, offset: usize, data: [u8; BYTES]) -> Result<(), BufferError> {
            check_length::<SIZE>(offset, BYTES)?;
            // Grow the buffer to the required size
            unsafe { self.set_len(core::cmp::max(self.len(), offset + BYTES)); };
            self.as_mut_slice()[offset..offset + BYTES].copy_from_slice(&data);

            Ok(())
        }

        #[inline(always)]
        fn write_bytes(&mut self, data: &[u8]) -> Result<(), BufferError> {
            check_length::<SIZE>(self.len(), data.len())?;
            self.try_extend_from_slice(data).map_err(|_| BufferError::OutOfMemory)?;

            Ok(())
        }

        #[inline(always)]
        fn write_array<const BYTES: usize>(&mut self, data: [u8; BYTES]) -> Result<(), BufferError> {
            check_length::<SIZE>(self.len(), BYTES)?;
            self.try_extend_from_slice(&data).map_err(|_| BufferError::OutOfMemory)?;

            Ok(())
        }

        #[inline(always)]
        fn read_bytes_at_mut(&mut self, offset: usize, length: usize) -> Result<&mut [u8], BufferError> {
            check_length::<SIZE>(offset, length)?;
            unsafe { self.set_len(core::cmp::max(self.len(), offset + length)); };
            Ok(&mut self.as_mut_slice()[offset..offset + length])
        }
    }
}

#[cfg(feature = "heapless")]
mod impl_heapless {
    use super::*;

    impl<const SIZE: usize> Buffer for heapless::Vec<u8, SIZE> {
        #[inline(always)]
        fn bytes(&self) -> &[u8] {
            self.as_slice()
        }

        #[inline(always)]
        fn len(&self) -> usize {
            self.bytes().len()
        }

        #[inline(always)]
        fn read_bytes_at(&self, offset: usize, length: usize) -> Result<&[u8], BufferError> {
            if offset + length > self.len() {
                if offset > self.len() {
                    return Err(BufferError::OffsetOutOfBounds);
                }
                return Err(BufferError::LengthOutOfBounds);
            }

            Ok(&self.as_slice()[offset..offset + length])
        }
    }

    impl<const SIZE: usize> MutBuffer for heapless::Vec<u8, SIZE> {
        #[inline(always)]
        fn truncate(&mut self, new_len: usize) -> Result<(), BufferError> {
            if new_len > self.len() {
                return Err(BufferError::InvalidLength);
            }

            heapless::Vec::truncate(self, new_len);
            Ok(())
        }

        #[inline(always)]
        fn write_array_at<const BYTES: usize>(&mut self, offset: usize, data: [u8; BYTES]) -> Result<(), BufferError> {
            check_length::<SIZE>(offset, BYTES)?;
            // Grow the buffer to the required size
            unsafe { self.set_len(core::cmp::max(self.len(), offset + BYTES)); };
            self[offset..offset + BYTES].copy_from_slice(&data);

            Ok(())
        }

        #[inline(always)]
        fn write_bytes(&mut self, data: &[u8]) -> Result<(), BufferError> {
            check_length::<SIZE>(self.len(), data.len())?;
            self.extend_from_slice(data).map_err(|_| BufferError::OutOfMemory)?;

            Ok(())
        }

        #[inline(always)]
        fn write_array<const BYTES: usize>(&mut self, data: [u8; BYTES]) -> Result<(), BufferError> {
            check_length::<SIZE>(self.len(), BYTES)?;
            self.extend_from_slice(&data).map_err(|_| BufferError::OutOfMemory)?;

            Ok(())
        }

        #[inline(always)]
        fn read_bytes_at_mut(&mut self, offset: usize, length: usize) -> Result<&mut [u8], BufferError> {
            check_length::<SIZE>(offset, length)?;
            unsafe { self.set_len(core::cmp::max(self.len(), offset + length)); };
            Ok(&mut self[offset..offset + length])
        }
    }
}

#[cfg(feature = "vec")]
mod impl_vec {
    extern crate alloc;

    use super::*;

    impl Buffer for alloc::vec::Vec<u8> {
        #[inline(always)]
        fn bytes(&self) -> &[u8] {
            self.as_slice()
        }

        #[inline(always)]
        fn len(&self) -> usize {
            <alloc::vec::Vec<u8>>::len(self)
        }

        #[inline(always)]
        fn read_bytes_at(&self, offset: usize, length: usize) -> Result<&[u8], BufferError> {
            if offset + length > self.len() {
                if offset > self.len() {
                    return Err(BufferError::OffsetOutOfBounds);
                }
                return Err(BufferError::LengthOutOfBounds);
            }

            Ok(&self.as_slice()[offset..offset + length])
        }
    }

    impl MutBuffer for alloc::vec::Vec<u8> {
        #[inline(always)]
        fn truncate(&mut self, new_len: usize) -> Result<(), BufferError> {
            if new_len > self.len() {
                return Err(BufferError::InvalidLength);
            }

            <alloc::vec::Vec<u8>>::truncate(self, new_len);
            Ok(())
        }

        #[inline(always)]
        fn write_array_at<const BYTES: usize>(&mut self, offset: usize, data: [u8; BYTES]) -> Result<(), BufferError> {
            if offset + BYTES > self.len() {
                if offset > self.len() {
                    return Err(BufferError::OffsetOutOfBounds);
                }
                return Err(BufferError::LengthOutOfBounds);
            }

            self.as_mut_slice()[offset..offset + BYTES].copy_from_slice(&data);

            Ok(())
        }

        #[inline(always)]
        fn write_bytes(&mut self, data: &[u8]) -> Result<(), BufferError> {
            self.extend_from_slice(data);
            Ok(())
        }

        #[inline(always)]
        fn write_array<const BYTES: usize>(&mut self, data: [u8; BYTES]) -> Result<(), BufferError> {
            self.extend_from_slice(&data);
            Ok(())
        }

        #[inline(always)]
        fn read_bytes_at_mut(&mut self, offset: usize, length: usize) -> Result<&mut [u8], BufferError> {
            if offset + length > self.len() {
                if offset > self.len() {
                    return Err(BufferError::OffsetOutOfBounds);
                }
                return Err(BufferError::LengthOutOfBounds);
            }

            Ok(&mut self.as_mut_slice()[offset..offset + length])
        }
    }
}