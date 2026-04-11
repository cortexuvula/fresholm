use pyo3::prelude::*;

mod account;
mod errors;
mod session;

#[pymodule(name = "_native")]
fn fresholm_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    errors::register_exceptions(m)?;
    m.add_class::<account::Account>()?;
    m.add_class::<session::Session>()?;
    Ok(())
}
