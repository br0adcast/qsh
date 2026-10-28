//! Direct system-build libselinux adapter. No host label operation runs in tests.
use super::Adapter;
use std::ffi::{c_char, c_int, CStr, CString};
use std::io;
use std::os::fd::RawFd;
use std::ptr;

pub(crate) struct Native;

#[link(name = "selinux")]
unsafe extern "C" {
    fn is_selinux_enabled() -> c_int;
    fn getexeccon(context: *mut *mut c_char) -> c_int;
    fn fgetfilecon(fd: c_int, context: *mut *mut c_char) -> c_int;
    fn security_compute_relabel(
        source: *const c_char,
        target: *const c_char,
        class: u16,
        context: *mut *mut c_char,
    ) -> c_int;
    fn string_to_security_class(name: *const c_char) -> u16;
    fn fsetfilecon(fd: c_int, context: *const c_char) -> c_int;
    fn freecon(context: *mut c_char);
}

// libselinux returns an owned, NUL-terminated allocation (or NULL for an unset
// pending exec context). Copy it while owned and release on every return path.
fn context_result(result: c_int, context: *mut c_char) -> io::Result<Option<CString>> {
    let result = if result < 0 {
        Err(io::Error::last_os_error())
    } else if context.is_null() {
        Ok(None)
    } else {
        // SAFETY: successful libselinux context output is NUL-terminated and
        // remains valid until the freecon immediately below.
        Ok(Some(unsafe { CStr::from_ptr(context) }.to_owned()))
    };
    if !context.is_null() {
        // SAFETY: this exact output allocation belongs to libselinux.
        unsafe { freecon(context) };
    }
    result
}
fn required(context: Option<CString>) -> io::Result<CString> {
    context
        .filter(|value| !value.as_bytes().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "libselinux returned no terminal context",
            )
        })
}
impl Adapter for Native {
    fn enabled(&self) -> io::Result<bool> {
        // SAFETY: no arguments or ownership transfer.
        match unsafe { is_selinux_enabled() } {
            value if value < 0 => Err(io::Error::last_os_error()),
            0 => Ok(false),
            _ => Ok(true),
        }
    }
    fn selected(&self) -> io::Result<Option<CString>> {
        let mut context = ptr::null_mut();
        // SAFETY: output storage is valid, initialized NULL, consumed exactly once.
        let result = unsafe { getexeccon(&mut context) };
        context_result(result, context)?
            .map(|context| required(Some(context)))
            .transpose()
    }
    fn label(&self, fd: RawFd) -> io::Result<CString> {
        let mut context = ptr::null_mut();
        // SAFETY: caller retains the live descriptor; output storage is valid.
        let result = unsafe { fgetfilecon(fd, &mut context) };
        required(context_result(result, context)?)
    }
    fn compute(&self, selected: &CStr, original: &CStr) -> io::Result<CString> {
        // SAFETY: static NUL-terminated class name.
        let class = unsafe { string_to_security_class(c"chr_file".as_ptr()) };
        if class == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "libselinux has no chr_file security class",
            ));
        }
        let mut context = ptr::null_mut();
        // SAFETY: both strings remain live, and output storage is valid.
        let result = unsafe {
            security_compute_relabel(selected.as_ptr(), original.as_ptr(), class, &mut context)
        };
        required(context_result(result, context)?)
    }
    fn set(&self, fd: RawFd, context: &CStr) -> io::Result<()> {
        // SAFETY: caller retains the descriptor and NUL-terminated context.
        if unsafe { fsetfilecon(fd, context.as_ptr()) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unset_exec_output_is_distinct_from_missing_required_terminal_label() {
        assert!(context_result(0, ptr::null_mut()).unwrap().is_none());
        assert_eq!(
            required(None).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(required(Some(CString::new("").unwrap())).is_err());
    }
    #[test]
    fn direct_native_adapter_links_all_entry_points_without_running_them() {
        // Taking these method addresses makes this a linkage check, not a host
        // SELinux operation or evidence of enforcing behavior.
        let methods = [
            Native::enabled as *const (),
            Native::selected as *const (),
            Native::label as *const (),
            Native::compute as *const (),
            Native::set as *const (),
        ];
        std::hint::black_box(methods);
    }
}
