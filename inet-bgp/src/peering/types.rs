use crate::types::AsNumber;

#[derive(Debug)]
pub(crate) enum PeeringKind {
    Internal,
    External,
}

impl PeeringKind {
    pub fn for_as(host: AsNumber, peer: AsNumber) -> Self {
        if host == peer {
            Self::Internal
        } else {
            Self::External
        }
    }
}
