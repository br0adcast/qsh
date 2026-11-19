//! Private ancillary ownership plumbing; sender observations grant no authority.
//!
//! nix refuses MSG_CTRUNC before exposing installed SCM_RIGHTS. Capture the
//! bounded installed prefix first, so callers can refuse it with custody intact.
use std::io;
use std::mem::{size_of, MaybeUninit};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use nix::sys::socket::MsgFlags;

pub(crate) struct Packet {
    pub(crate) bytes: usize,
    pub(crate) flags: MsgFlags,
    pub(crate) descriptors: Vec<OwnedFd>,
    pub(crate) sender: Option<i32>,
    pub(crate) unsupported: bool,
    pub(crate) rights: bool,
    pub(crate) any_control: bool,
}

pub(crate) const fn space<T>() -> usize {
    // SAFETY: all callers use fixed, bounded ancillary element types.
    unsafe { nix::libc::CMSG_SPACE(size_of::<T>() as nix::libc::c_uint) as usize }
}

/// Aligned and explicitly initialized before the kernel can install descriptors.
struct ControlStorage {
    storage: Vec<MaybeUninit<nix::libc::cmsghdr>>,
    bytes: usize,
}
impl ControlStorage {
    fn new(bytes: usize) -> Self {
        let count = bytes.div_ceil(size_of::<nix::libc::cmsghdr>());
        let mut storage = Vec::with_capacity(count);
        storage.resize_with(count, MaybeUninit::uninit);
        // SAFETY: this initialized byte range is the allocated, aligned backing;
        // it remains at the same address throughout receive and prefix walking.
        unsafe {
            std::ptr::write_bytes(
                storage.as_mut_ptr().cast::<u8>(),
                0,
                count * size_of::<nix::libc::cmsghdr>(),
            );
        }
        Self { storage, bytes }
    }
    fn pointer(&self) -> *const u8 {
        self.storage.as_ptr().cast()
    }
}

#[derive(Default)]
struct Observed {
    sender: Option<i32>,
    unsupported: bool,
    rights: bool,
    any_control: bool,
}

/// Walk only structurally located messages within the initialized prefix.
/// The observation sink is deliberately separate from descriptor ownership so
/// structural tests never adopt an invented descriptor number.
fn collect_prefix(
    storage: &ControlStorage,
    initialized: usize,
    mut descriptor: impl FnMut(RawFd),
) -> Observed {
    let limit = initialized.min(storage.bytes);
    let mut observed = Observed {
        unsupported: initialized > storage.bytes,
        ..Observed::default()
    };
    // SAFETY: the platform macro computes only the fixed header extent.
    let minimum = unsafe { nix::libc::CMSG_LEN(0) as usize };
    let mut offset = 0usize;
    #[cfg(target_os = "linux")]
    let mut credentials_seen = false;
    while offset < limit {
        observed.any_control = true;
        if limit - offset < size_of::<nix::libc::cmsghdr>() {
            observed.unsupported = true;
            break;
        }
        // SAFETY: the complete header is in the initialized, bounded backing.
        // read_unaligned forms no reference to potentially unaligned input.
        let header = unsafe {
            storage
                .pointer()
                .add(offset)
                .cast::<nix::libc::cmsghdr>()
                .read_unaligned()
        };
        #[cfg(target_os = "linux")]
        let declared = header.cmsg_len;
        #[cfg(not(target_os = "linux"))]
        let declared = header.cmsg_len as usize;
        if declared < minimum || minimum > limit - offset {
            observed.unsupported = true;
            break;
        }
        let available = declared.min(limit - offset) - minimum;
        let payload_offset = offset + minimum; // bounded by limit above
        let truncated = declared > limit - offset;
        observed.unsupported |= truncated;
        if header.cmsg_level == nix::libc::SOL_SOCKET && header.cmsg_type == nix::libc::SCM_RIGHTS {
            observed.rights = true;
            observed.unsupported |= !available.is_multiple_of(size_of::<RawFd>());
            for index in 0..available / size_of::<RawFd>() {
                // SAFETY: each complete integer fits in this record's bounded
                // payload; neither header padding nor unknown payload is read.
                let raw = unsafe {
                    storage
                        .pointer()
                        .add(payload_offset + index * size_of::<RawFd>())
                        .cast::<RawFd>()
                        .read_unaligned()
                };
                if raw < 0 {
                    observed.unsupported = true;
                } else {
                    descriptor(raw);
                }
            }
        } else {
            #[cfg(target_os = "linux")]
            if header.cmsg_level == nix::libc::SOL_SOCKET
                && header.cmsg_type == nix::libc::SCM_CREDENTIALS
            {
                observed.unsupported |= credentials_seen;
                credentials_seen = true;
                if !truncated && available == size_of::<nix::libc::ucred>() {
                    // SAFETY: the complete fixed credential record fits; all
                    // fields are integers and this observation grants no authority.
                    let credentials = unsafe {
                        storage
                            .pointer()
                            .add(payload_offset)
                            .cast::<nix::libc::ucred>()
                            .read_unaligned()
                    };
                    observed.sender = Some(credentials.pid);
                } else {
                    observed.unsupported = true;
                }
            } else {
                observed.unsupported = true;
            }
            #[cfg(not(target_os = "linux"))]
            {
                observed.unsupported = true;
            }
        }
        if truncated {
            break; // there cannot be another complete, located record
        }
        let payload_len = declared - minimum;
        // Bound the macro argument and its alignment/header arithmetic before
        // invoking the platform layout macro (whose result is a c_uint).
        let Some(argument) = u32::try_from(payload_len).ok().filter(|length| {
            (*length as usize) <= u32::MAX as usize - space::<nix::libc::cmsghdr>()
        }) else {
            observed.unsupported = true;
            break;
        };
        // SAFETY: the bound above leaves room for the platform header/alignment.
        let step = unsafe { nix::libc::CMSG_SPACE(argument) as usize };
        let Some(next) = offset.checked_add(step).filter(|next| *next > offset) else {
            observed.unsupported = true;
            break;
        };
        if next >= limit {
            break; // any remaining bytes are this final record's alignment padding
        }
        offset = next;
    }
    observed
}

pub(crate) fn receive(
    socket: BorrowedFd<'_>,
    payload: &mut [u8],
    control_bytes: usize,
    flags: MsgFlags,
) -> io::Result<Packet> {
    let mut control = ControlStorage::new(control_bytes);
    // Alignment slack can install more descriptors than a caller's logical fd
    // count. Every possible complete integer in the entire byte bound has a
    // preallocated guard slot before the kernel can install anything.
    let mut descriptors = Vec::<OwnedFd>::with_capacity(control_bytes / size_of::<RawFd>());
    let mut vector = nix::libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    // SAFETY: all-zero msghdr has null absent address/control pointers and zero
    // lengths; all pointers used by recvmsg are supplied below and remain live.
    let mut message: nix::libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = if control_bytes == 0 {
        std::ptr::null_mut()
    } else {
        control.storage.as_mut_ptr().cast()
    };
    message.msg_controllen = control_bytes as _;
    // SAFETY: socket is genuinely borrowed; payload and initialized/aligned
    // control backing are writable for exactly the supplied lengths. This is
    // one syscall, with the caller's original flags and no consuming retry.
    let count = unsafe { nix::libc::recvmsg(socket.as_raw_fd(), &mut message, flags.bits()) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut capacity_failed = false;
    let observed = collect_prefix(&control, message.msg_controllen as usize, |raw| {
        // SAFETY: only complete nonnegative SCM_RIGHTS integers returned by the
        // kernel enter this production callback. Each is adopted exactly once.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        let length = descriptors.len();
        if length == descriptors.capacity() {
            // Defensive refusal still closes this installed descriptor and
            // continues custody collection without allocating.
            drop(owned);
            capacity_failed = true;
        } else {
            // SAFETY: length < capacity proves this preallocated slot exists;
            // write and set_len transfer sole ownership without allocator calls.
            unsafe {
                descriptors.as_mut_ptr().add(length).write(owned);
                descriptors.set_len(length + 1);
            }
        }
    });
    Ok(Packet {
        bytes: count as usize,
        flags: MsgFlags::from_bits_retain(message.msg_flags),
        descriptors,
        sender: observed.sender,
        unsupported: observed.unsupported || capacity_failed || count as usize > payload.len(),
        rights: observed.rights,
        any_control: observed.any_control,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn header(
        storage: &mut ControlStorage,
        offset: usize,
        data: &[u8],
        declared: usize,
        kind: i32,
    ) {
        let minimum = unsafe { nix::libc::CMSG_LEN(0) as usize };
        assert!(offset.checked_add(size_of::<nix::libc::cmsghdr>()).unwrap() <= storage.bytes);
        assert!(
            offset
                .checked_add(minimum)
                .unwrap()
                .checked_add(data.len())
                .unwrap()
                <= storage.bytes
        );
        // SAFETY: the complete header and copied data fit the initialized backing.
        let start = unsafe { storage.storage.as_mut_ptr().cast::<u8>().add(offset) };
        let pointer = start.cast::<nix::libc::cmsghdr>();
        // These are abstract parser inputs. No test constructs or closes an fd.
        unsafe {
            std::ptr::addr_of_mut!((*pointer).cmsg_len).write_unaligned(declared as _);
            std::ptr::addr_of_mut!((*pointer).cmsg_level).write_unaligned(nix::libc::SOL_SOCKET);
            std::ptr::addr_of_mut!((*pointer).cmsg_type).write_unaligned(kind);
            let payload = start.add(nix::libc::CMSG_LEN(0) as usize);
            std::ptr::copy_nonoverlapping(data.as_ptr(), payload, data.len());
        }
    }
    fn integers(values: &[RawFd]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_ne_bytes())
            .collect()
    }
    #[test]
    fn complete_rights_are_observed_without_creating_descriptor_owners() {
        let mut storage = ControlStorage::new(space::<[RawFd; 2]>());
        let bytes = integers(&[37, 41]);
        let declared = unsafe { nix::libc::CMSG_LEN(bytes.len() as _) as usize };
        header(&mut storage, 0, &bytes, declared, nix::libc::SCM_RIGHTS);
        let mut seen = Vec::new();
        let observed = collect_prefix(&storage, storage.bytes, |fd| seen.push(fd));
        assert_eq!(seen, [37, 41]);
        assert!(observed.rights && observed.any_control && !observed.unsupported);
    }
    #[test]
    fn partial_rights_preserve_complete_integer_observations_before_refusal() {
        let mut storage = ControlStorage::new(space::<[RawFd; 3]>());
        let mut bytes = integers(&[37]);
        bytes.extend([1, 2]);
        let declared = unsafe { nix::libc::CMSG_LEN(12) as usize };
        header(&mut storage, 0, &bytes, declared, nix::libc::SCM_RIGHTS);
        let initialized = unsafe { nix::libc::CMSG_LEN(bytes.len() as _) as usize };
        let mut seen = Vec::new();
        let observed = collect_prefix(&storage, initialized, |fd| seen.push(fd));
        assert_eq!(seen, [37]);
        assert!(observed.unsupported);
    }
    #[test]
    fn unsupported_record_does_not_hide_a_later_complete_rights_record() {
        let offset = space::<()>();
        let mut storage = ControlStorage::new(offset + space::<RawFd>());
        let minimum = unsafe { nix::libc::CMSG_LEN(0) as usize };
        header(&mut storage, 0, &[], minimum, i32::MAX);
        let bytes = integers(&[43]);
        let declared = unsafe { nix::libc::CMSG_LEN(bytes.len() as _) as usize };
        header(
            &mut storage,
            offset,
            &bytes,
            declared,
            nix::libc::SCM_RIGHTS,
        );
        let mut seen = Vec::new();
        let observed = collect_prefix(&storage, storage.bytes, |fd| seen.push(fd));
        assert_eq!(seen, [43]);
        assert!(observed.unsupported);
    }
    #[test]
    fn empty_prefix_is_valid_but_a_partial_header_is_refused() {
        let storage = ControlStorage::new(space::<RawFd>());
        let empty = collect_prefix(&storage, 0, |_| panic!("no descriptor"));
        assert!(!empty.unsupported && !empty.any_control && !empty.rights);
        let partial = collect_prefix(&storage, size_of::<nix::libc::cmsghdr>() - 1, |_| {
            panic!("no complete header")
        });
        assert!(partial.unsupported);
    }
    #[test]
    fn invalid_length_cannot_expose_padding_as_descriptors() {
        let mut storage = ControlStorage::new(space::<RawFd>());
        header(&mut storage, 0, &integers(&[37]), 1, nix::libc::SCM_RIGHTS);
        let observed = collect_prefix(&storage, storage.bytes, |_| {
            panic!("invalid header has no payload")
        });
        assert!(observed.unsupported);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn duplicate_credentials_refuse_but_still_observe_later_rights() {
        let credentials = nix::libc::ucred {
            pid: 123,
            uid: 456,
            gid: 789,
        };
        // SAFETY: ucred contains only initialized integer fields on Linux.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&credentials as *const nix::libc::ucred).cast::<u8>(),
                size_of::<nix::libc::ucred>(),
            )
        };
        let offset = space::<nix::libc::ucred>();
        let mut storage = ControlStorage::new(offset * 2 + space::<RawFd>());
        let declared = unsafe { nix::libc::CMSG_LEN(bytes.len() as _) as usize };
        header(&mut storage, 0, bytes, declared, nix::libc::SCM_CREDENTIALS);
        header(
            &mut storage,
            offset,
            bytes,
            declared,
            nix::libc::SCM_CREDENTIALS,
        );
        let descriptor = integers(&[43]);
        let declared = unsafe { nix::libc::CMSG_LEN(descriptor.len() as _) as usize };
        header(
            &mut storage,
            offset * 2,
            &descriptor,
            declared,
            nix::libc::SCM_RIGHTS,
        );
        let mut seen = Vec::new();
        let observed = collect_prefix(&storage, storage.bytes, |fd| seen.push(fd));
        assert_eq!(seen, [43]);
        assert_eq!(observed.sender, Some(123));
        assert!(observed.unsupported);
    }
}
