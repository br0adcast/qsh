//! Turning a terminal frame into bytes for someone else's terminal.

pub mod caps;
pub mod renderer;
pub mod sgr;

pub use caps::{ColorDepth, TermCaps};
pub use renderer::Renderer;
