use pyo3::prelude::*;

mod account;
mod errors;
mod group_session;
mod inbound_group_session;
mod pk;
mod session;

#[pymodule(name = "_native")]
fn fresholm_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    errors::register_exceptions(m)?;
    m.add_class::<account::Account>()?;
    m.add_class::<session::Session>()?;
    m.add_class::<session::EncryptedMessage>()?;
    m.add_class::<group_session::GroupSession>()?;
    m.add_class::<inbound_group_session::InboundGroupSession>()?;
    m.add_class::<pk::PkEncryption>()?;
    m.add_class::<pk::PkDecryption>()?;
    m.add_class::<pk::PkMessage>()?;
    Ok(())
}
