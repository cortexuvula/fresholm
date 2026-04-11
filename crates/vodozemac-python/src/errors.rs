use pyo3::create_exception;
use pyo3::prelude::*;

create_exception!(fresholm._native, OlmError, pyo3::exceptions::PyException);
create_exception!(fresholm._native, OlmSessionError, OlmError);
create_exception!(fresholm._native, OlmGroupSessionError, OlmError);
create_exception!(fresholm._native, OlmAccountError, OlmError);
create_exception!(fresholm._native, CryptoStoreError, pyo3::exceptions::PyException);

pub fn register_exceptions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("OlmError", m.py().get_type::<OlmError>())?;
    m.add("OlmSessionError", m.py().get_type::<OlmSessionError>())?;
    m.add("OlmGroupSessionError", m.py().get_type::<OlmGroupSessionError>())?;
    m.add("OlmAccountError", m.py().get_type::<OlmAccountError>())?;
    m.add("CryptoStoreError", m.py().get_type::<CryptoStoreError>())?;
    Ok(())
}
