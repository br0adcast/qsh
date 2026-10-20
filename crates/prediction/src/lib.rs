//! Input prediction (local echo) for the portable core: a port of mosh's
//! `terminaloverlay` logic. Operates on a `terminal::Frame` grid snapshot --
//! no terminal implementation or foreign-language bindings. `PredictionEngine` is the public surface
//! (see `engine`).

mod budget;

pub mod engine;
pub mod keystroke;
pub mod overlay;

pub use engine::{DisplayPreference, PredictionEngine};
