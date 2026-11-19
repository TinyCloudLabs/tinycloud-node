//! Fixed-order, big-endian encoding for construction-bounded crate values.

use crate::error::Error;

const MESSAGE_CAP: usize = 65_536;

/// An encoder for validated fields whose complete message fits the message cap.
///
/// Callers supply only construction-bounded fields: `lp` lengths are at most
/// 64 KiB, and complete encoded messages are at most 64 KiB. Untrusted lengths
/// enter through `Decoder`, not this encoder.
#[derive(Default)]
pub(crate) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.fixed(&value.to_be_bytes());
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.fixed(&value.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.fixed(&value.to_be_bytes());
    }

    pub(crate) fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn lp(&mut self, value: &[u8]) {
        // Every field is construction-bounded to <= 64 KiB by the caller.
        self.u32(value.len() as u32);
        self.fixed(value);
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// A borrowed decoder that bounds lengths before returning a field slice.
pub(crate) struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() > MESSAGE_CAP {
            return Err(Error::LimitExceeded);
        }
        Ok(Self { remaining: bytes })
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(Error::InvalidLength)?;
        self.remaining = remaining;
        Ok(value)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        let [value] = self.fixed()?;
        Ok(value)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::InvalidLength)
    }

    pub(crate) fn lp(&mut self, cap: usize) -> Result<&'a [u8], Error> {
        let length = usize::try_from(self.u32()?).map_err(|_| Error::LimitExceeded)?;
        if length > cap {
            return Err(Error::LimitExceeded);
        }
        self.take(length)
    }

    pub(crate) fn finish(self) -> Result<(), Error> {
        if !self.remaining.is_empty() {
            return Err(Error::InvalidEncoding);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn fixed_width_and_length_prefixed_encoding_is_big_endian() {
        let mut encoder = Encoder::new();
        encoder.u8(1);
        encoder.u16(0x0203);
        encoder.u32(0x04050607);
        encoder.u64(0x08090a0b0c0d0e0f);
        encoder.fixed(&[16, 17]);
        encoder.lp(&[18, 19]);
        let bytes = encoder.finish();
        assert_eq!(
            bytes,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 0, 0, 0, 2, 18, 19]
        );
        let mut decoder = Decoder::new(&bytes).unwrap();
        assert_eq!(decoder.u8(), Ok(1));
        assert_eq!(decoder.u16(), Ok(0x0203));
        assert_eq!(decoder.u32(), Ok(0x04050607));
        assert_eq!(decoder.u64(), Ok(0x08090a0b0c0d0e0f));
        assert_eq!(decoder.fixed::<2>(), Ok([16, 17]));
        assert_eq!(decoder.lp(2), Ok([18, 19].as_slice()));
        assert_eq!(decoder.finish(), Ok(()));
    }

    #[test]
    fn decoder_rejects_limits_truncation_and_trailing_bytes() {
        assert!(matches!(
            Decoder::new(&vec![0; 65537]),
            Err(Error::LimitExceeded)
        ));
        assert!(Decoder::new(&vec![0; 65536]).is_ok());
        assert_eq!(Decoder::new(&[]).unwrap().u8(), Err(Error::InvalidLength));
        assert_eq!(Decoder::new(&[0]).unwrap().u16(), Err(Error::InvalidLength));
        assert_eq!(
            Decoder::new(&[0; 3]).unwrap().u32(),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            Decoder::new(&[0; 7]).unwrap().u64(),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            Decoder::new(&[0; 7]).unwrap().fixed::<8>(),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            Decoder::new(&[0]).unwrap().finish(),
            Err(Error::InvalidEncoding)
        );
        assert_eq!(
            Decoder::new(&[0, 0, 0, 1]).unwrap().lp(1),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            Decoder::new(&[0xff; 4]).unwrap().lp(1024),
            Err(Error::LimitExceeded)
        );
        assert_eq!(
            Decoder::new(&[0, 0, 0, 2, 1, 2]).unwrap().lp(1),
            Err(Error::LimitExceeded)
        );
        assert_eq!(
            Decoder::new(&[0, 0, 0, 0]).unwrap().lp(0),
            Ok([].as_slice())
        );
    }

    proptest! {
        #[test]
        fn random_decoder_input_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..70000)) {
            if let Ok(mut decoder) = Decoder::new(&bytes) {
                let _ = decoder.u8();
                let _ = decoder.u16();
                let _ = decoder.u32();
                let _ = decoder.u64();
                let _ = decoder.fixed::<32>();
                let _ = decoder.lp(1024);
                let _ = decoder.finish();
            }
        }
    }
}
