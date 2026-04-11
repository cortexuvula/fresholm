use pyo3::prelude::*;

#[pyclass]
pub struct Session {
    pub(crate) inner: vodozemac::olm::Session,
}

impl Session {
    pub fn from_vz(inner: vodozemac::olm::Session) -> Self {
        Self { inner }
    }
}
