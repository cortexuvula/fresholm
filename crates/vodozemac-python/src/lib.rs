use pyo3::prelude::*;

#[pymodule(name = "_native")]
fn fresholm_native(_m: &Bound<'_, PyModule>) -> PyResult<()> {
    Ok(())
}
