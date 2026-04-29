use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

mod account;
mod errors;
mod group_session;
mod inbound_group_session;
mod pickle_format;
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
    m.add_function(wrap_pyfunction!(account::_v1_encrypt_account_for_testing, m)?)?;
    m.add_function(wrap_pyfunction!(session::_v1_encrypt_session_for_testing, m)?)?;
    Ok(())
}
