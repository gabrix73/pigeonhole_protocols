//! Pigeonhole over a Reticulum mesh, through the Python mesh transport: this embeds CPython and
//! calls `pigeonhole_protocols.transport.reticulum.MeshBackend`, which does BACAP with hpqc and
//! talks to the nearest replica through `pigeonhole_rns`. It suits desktops, where Python runs;
//! Android needs a native Reticulum.
//!
//! The Python packages `pigeonhole_protocols` (with its `reticulum` extra), `pigeonhole_rns`,
//! `hpqc` and `RNS` must be importable by the embedded interpreter, the Python this crate was
//! built against (`PYO3_PYTHON`). Its `sys.path` comes from that Python's installation and
//! `PYTHONPATH`; a virtual environment named by `VIRTUAL_ENV` is added too, with its `.pth` files.
//!
//! Every call runs on a blocking thread with the Python interpreter attached, since the mesh
//! blocks while a replica answers.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::transport::{Backend, Error, Inducted, Keypair, Minted, Opened, Pushed, Read, Result, Secret};

const MESH: &str = "pigeonhole_protocols.transport.reticulum";
const BASE: &str = "pigeonhole_protocols.transport.base";
const ENGINE: &str = "pigeonhole_protocols.katzenqt1.engine";

/// A [`Backend`] over a Python `MeshBackend`, or any Python object with its methods.
#[derive(Clone)]
pub struct ReticulumPyBackend {
    obj: Arc<Py<PyAny>>,
}

/// Prepares the embedded interpreter: adds the virtual environment `VIRTUAL_ENV` names to
/// `sys.path`, with its `.pth` files, which an embedded interpreter does not find by itself. Doing
/// so again changes nothing. The constructors call it; call it before using Python here directly.
/// Fails with the Python error as [`Error::Other`].
pub fn init_python() -> Result<()> {
    Python::attach(|py| init(py).map_err(|e| error(py, e)))
}

// Not behind a Once: a thread waiting on it while attached would hold the GIL that the thread
// running it, which releases the GIL while importing, needs back.
fn init(py: Python<'_>) -> PyResult<()> {
    let Ok(venv) = std::env::var("VIRTUAL_ENV") else {
        return Ok(());
    };
    let v = py.version_info();
    let dir = format!("{venv}/lib/python{}.{}/site-packages", v.major, v.minor);
    py.import("site")?.call_method1("addsitedir", (dir,))?;
    Ok(())
}

/// The transport error a Python exception is: `BoxExists` is [`Error::BoxAlreadyExists`]; a
/// `TransportError`, a call that may succeed if tried again, is [`Error::Other`] with its message,
/// as every other transport's failures are; anything else is [`Error::Other`] naming the Python
/// exception.
fn error(py: Python<'_>, e: PyErr) -> Error {
    let is = |name: &str| {
        py.import(BASE)
            .and_then(|m| m.getattr(name))
            .and_then(|c| e.value(py).is_instance(&c))
            .unwrap_or(false)
    };
    if is("BoxExists") {
        Error::BoxAlreadyExists
    } else if is("TransportError") {
        Error::Other(e.value(py).to_string())
    } else {
        Error::Other(format!("python: {e}"))
    }
}

fn bytes(o: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    Ok(o.cast::<PyBytes>()?.as_bytes().to_vec())
}

fn field(o: &Bound<'_, PyAny>, name: &str) -> PyResult<Vec<u8>> {
    bytes(&o.getattr(name)?)
}

/// Runs `f` on a blocking thread with the interpreter attached.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce(Python<'_>) -> PyResult<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(move || Python::attach(|py| f(py).map_err(|e| error(py, e))))
        .await
        .map_err(|e| Error::Other(e.to_string()))?
}

impl ReticulumPyBackend {
    /// Attaches to the Reticulum instance `config_dir` describes (a running shared instance, or
    /// one started in this process; `None` is Reticulum's default) through `MeshBackend.connect`,
    /// with boxes holding `box_size` bytes of plaintext, and waits up to `wait` for a replica.
    ///
    /// Reticulum starts only on Python's main thread, the thread that first used Python, so call
    /// this from that thread before any other use of Python here; it blocks that thread while
    /// Reticulum starts. The signal handlers Reticulum installs are put back to the defaults,
    /// since Python would run them only while that thread runs Python, and so a Ctrl-C would
    /// never stop the process.
    ///
    /// Fails with [`Error::Other`] when no replica is heard in time (`TransportError`), or when
    /// the packages are missing or Reticulum does not start (the Python error).
    pub async fn connect(config_dir: Option<&Path>, box_size: usize, wait: Duration) -> Result<Self> {
        Self::connect_mode(config_dir, box_size, wait, "auto").await
    }

    /// [`connect`](Self::connect) with a query mode: `"request"` (Link requests and Resources),
    /// `"channel"` (Channel messages, for replicas announcing it) or `"auto"`: requests first,
    /// falling back to Channel per replica.
    pub async fn connect_mode(config_dir: Option<&Path>, box_size: usize, wait: Duration, mode: &str) -> Result<Self> {
        let boxes = Python::attach(|py| {
            (|| {
                init(py)?;
                let rns = py.import("RNS")?;
                let client = py.import(MESH)?.getattr("Boxes")?;
                let kw = pyo3::types::PyDict::new(py);
                kw.set_item("loglevel", rns.getattr("LOG_ERROR")?)?;
                kw.set_item("mode", mode)?;
                let dir = config_dir.map(|d| d.to_string_lossy().into_owned());
                let boxes = client.call((dir, box_size), Some(&kw))?;
                let signal = py.import("signal")?;
                for s in ["SIGINT", "SIGTERM"] {
                    signal.call_method1("signal", (signal.getattr(s)?, signal.getattr("SIG_DFL")?))?;
                }
                Ok(boxes.unbind())
            })()
            .map_err(|e| error(py, e))
        })?;
        let wait = wait.as_secs_f64();
        let obj = blocking(move |py| {
            let mesh = py.import(MESH)?.getattr("MeshBackend")?;
            Ok(mesh.call_method1("wait_for", (boxes, wait))?.unbind())
        })
        .await?;
        Ok(Self { obj: Arc::new(obj) })
    }

    /// Wraps a Python object with `MeshBackend`'s methods, such as a `MeshBackend` over a stand-in
    /// for the box client in tests.
    pub fn from_object(obj: Py<PyAny>) -> Self {
        Python::attach(|py| {
            let _ = init(py);
        });
        Self { obj: Arc::new(obj) }
    }

    /// The Python object called.
    pub fn object(&self) -> &Py<PyAny> {
        &self.obj
    }

    async fn call<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Bound<'_, PyAny>) -> PyResult<T> + Send + 'static,
    ) -> Result<T> {
        let obj = self.obj.clone();
        blocking(move |py| f(obj.bind(py))).await
    }

    /// The entry replica and how many hops away it is, for a log line.
    pub async fn entry(&self) -> Result<String> {
        self.call(|o| o.call_method0("where")?.extract()).await
    }

    /// Closes the box client and its link to the replica.
    pub async fn close(&self) -> Result<()> {
        self.call(|o| o.call_method0("close").map(|_| ())).await
    }
}

impl Backend for ReticulumPyBackend {
    async fn new_keypair(&self) -> Result<Keypair> {
        self.call(|o| {
            let k = o.call_method0("new_keypair")?;
            Ok(Keypair {
                write_cap: field(&k, "write_cap")?.into(),
                read_cap: field(&k, "read_cap")?.into(),
                first: field(&k, "first")?,
            })
        })
        .await
    }

    async fn write_box(&self, write_cap: &[u8], index: &[u8], plaintext: &[u8]) -> Result<()> {
        let a = (Secret::from(write_cap.to_vec()), index.to_vec(), plaintext.to_vec());
        self.call(move |o| {
            let py = o.py();
            o.call_method1(
                "write_box",
                (PyBytes::new(py, &a.0), PyBytes::new(py, &a.1), PyBytes::new(py, &a.2)),
            )
            .map(|_| ())
        })
        .await
    }

    async fn read_box(&self, read_cap: &[u8], index: &[u8]) -> Result<Read> {
        let a = (read_cap.to_vec(), index.to_vec());
        self.call(move |o| {
            let py = o.py();
            let out = o.call_method1("read_box", (PyBytes::new(py, &a.0), PyBytes::new(py, &a.1)))?;
            let engine = py.import(ENGINE)?;
            let kind = out.getattr("kind")?;
            if kind.eq(engine.getattr("DATA")?)? {
                Ok(Read::Data(field(&out, "plaintext")?))
            } else if kind.eq(engine.getattr("TOMBSTONE")?)? {
                Ok(Read::Tombstone)
            } else {
                Ok(Read::NotFound)
            }
        })
        .await
    }

    /// `MeshBackend.watch`, its callback a Rust closure that sends on the receiver.
    async fn watch(&self, read_cap: &[u8], index: &[u8]) -> Option<Pushed> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let tx = std::sync::Mutex::new(Some(tx));
        let a = (read_cap.to_vec(), index.to_vec());
        let ok = self
            .call(move |o| {
                let py = o.py();
                let on_box = pyo3::types::PyCFunction::new_closure(py, None, None, move |_, _| {
                    if let Some(tx) = tx.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                })?;
                o.call_method1("watch", (PyBytes::new(py, &a.0), PyBytes::new(py, &a.1), on_box))?
                    .extract::<bool>()
            })
            .await;
        matches!(ok, Ok(true)).then_some(rx)
    }

    async fn replica_epoch(&self) -> Result<u64> {
        self.call(|o| o.call_method0("replica_epoch")?.extract()).await
    }

    async fn max_plaintext(&self) -> Result<usize> {
        self.call(|o| o.call_method0("max_plaintext")?.extract()).await
    }

    async fn voucher_mint(&self, write_cap: &[u8], name: &str, form: u8) -> Result<Minted> {
        let a = (Secret::from(write_cap.to_vec()), name.to_string());
        self.call(move |o| {
            let m = o.call_method1("voucher_mint", (PyBytes::new(o.py(), &a.0), a.1, form))?;
            Ok(Minted {
                voucher: field(&m, "voucher")?.into(),
                payload: field(&m, "payload")?.into(),
                write_cap: field(&m, "write_cap")?.into(),
                read_cap: field(&m, "read_cap")?.into(),
                secret_key: field(&m, "secret_key")?.into(),
                version: m.getattr("version")?.extract()?,
            })
        })
        .await
    }

    async fn voucher_derive_stream(&self, voucher: &[u8]) -> Result<(Secret, Secret)> {
        let v = Secret::from(voucher.to_vec());
        self.call(move |o| {
            let r = o.call_method1("voucher_derive_stream", (PyBytes::new(o.py(), &v),))?;
            Ok((bytes(&r.get_item(0)?)?.into(), bytes(&r.get_item(1)?)?.into()))
        })
        .await
    }

    async fn voucher_induct(&self, voucher: &[u8], payload: &[u8], who_reply: &[u8]) -> Result<Inducted> {
        let a = (Secret::from(voucher.to_vec()), payload.to_vec(), Secret::from(who_reply.to_vec()));
        self.call(move |o| {
            let py = o.py();
            let r = o.call_method1(
                "voucher_induct",
                (PyBytes::new(py, &a.0), PyBytes::new(py, &a.1), PyBytes::new(py, &a.2)),
            )?;
            Ok(Inducted {
                name: r.getattr("name")?.extract()?,
                mutated_read_cap: field(&r, "mutated_read_cap")?.into(),
                sealed_reply: field(&r, "sealed_reply")?,
                version: r.getattr("version")?.extract()?,
            })
        })
        .await
    }

    async fn voucher_open(&self, secret_key: &[u8], sealed_reply: &[u8], write_cap: &[u8]) -> Result<Opened> {
        let a = (Secret::from(secret_key.to_vec()), sealed_reply.to_vec(), Secret::from(write_cap.to_vec()));
        self.call(move |o| {
            let py = o.py();
            let r = o.call_method1(
                "voucher_open",
                (PyBytes::new(py, &a.0), PyBytes::new(py, &a.1), PyBytes::new(py, &a.2)),
            )?;
            Ok(Opened {
                who_reply: field(&r, "who_reply")?.into(),
                mutated_write_cap: field(&r, "mutated_write_cap")?.into(),
            })
        })
        .await
    }
}
