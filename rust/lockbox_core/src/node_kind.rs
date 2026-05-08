use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeKind {
    File = 1,
    Symlink = 2,
}

impl NodeKind {
    pub(crate) fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::File),
            2 => Ok(Self::Symlink),
            _ => Err(Error::CorruptRecord),
        }
    }
}
