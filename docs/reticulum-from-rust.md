# Reticulum from Rust

The Rust crate reaches a Reticulum mesh in two ways.

## Natively: `reticulum-rs`

The `reticulum-rs` cargo feature adds `transport::reticulum_rs`, which carries Pigeonhole boxes
over [berlinmesh/reticulum](https://git.emcomm.cc/berlinmesh/reticulum) in Rust. Its end to end
tests against the Python and Rust `pigeonhole_rns` replicas are in `rust/tests/reticulum_rs.rs`.
This is the path for Android.

## Through Python: `reticulum-py`

The `reticulum-py` cargo feature adds `transport::reticulum_py::ReticulumPyBackend`, which embeds
CPython and calls the Python mesh transport, `py/pigeonhole_protocols/transport/reticulum.py`.
Rust clients such as hushphone then join a mesh as the Python ones do;
`katzenqt1-rs --mesh CONFIG_DIR [--box-size mesh|mixnet|N]` does from the command line.

At run time the Python the crate was built against (`PYO3_PYTHON`) must import
`pigeonhole_protocols` with its `reticulum` extra, `pigeonhole_rns` and `hpqc`; a virtual
environment is found through `VIRTUAL_ENV`:

```
pip install -e "py[reticulum]" "pigeonhole-rns @ git+https://github.com/katzenpost/pigeonhole_rns" \
  "hpqc @ git+https://github.com/katzenpost/hpqc@katzenqt1-v4#subdirectory=py"
cargo test --features reticulum-py --test transport_reticulum_py
```

This suits desktops.
