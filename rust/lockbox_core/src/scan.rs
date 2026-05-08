use crate::record::DecodedRecord;

#[derive(Debug)]
pub(crate) struct Scan {
    pub(crate) records: Vec<DecodedRecord>,
    pub(crate) corrupt_records: usize,
}
