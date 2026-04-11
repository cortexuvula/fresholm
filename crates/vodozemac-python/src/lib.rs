use pyo3::prelude::*;

mod errors;

#[pymodule(name = "_native")]
fn fresholm_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    errors::register_exceptions(m)?;
    Ok(())
}
