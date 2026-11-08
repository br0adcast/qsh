//! Borrowed, allocation-free preflight helpers for local-only contracts.
use super::authorization_contract::*;
use super::protocol::OwnerProtocolError as Error;
use transport::session_resume::*;
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    pub fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(len).ok_or(Error::TooLarge)?;
        let b = self.bytes.get(self.pos..end).ok_or(Error::Malformed)?;
        self.pos = end;
        Ok(b)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    pub fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub fn locator(&mut self) -> Result<SessionLocator, Error> {
        Ok(SessionLocator {
            session: RetainedSessionId::new(self.array()?).ok_or(Error::Malformed)?,
            owner: OwnerInstance::new(self.array()?).ok_or(Error::Malformed)?,
        })
    }
    pub fn frontend(&mut self) -> Result<FrontendGeneration, Error> {
        FrontendGeneration::new(self.array()?).ok_or(Error::Malformed)
    }
    pub fn attachment(&mut self) -> Result<Attachment, Error> {
        Ok(Attachment {
            locator: self.locator()?,
            frontend: self.frontend()?,
            epoch: AttachEpoch::new(self.u64()?).ok_or(Error::Malformed)?,
        })
    }
    pub fn principal(&mut self) -> Result<AuthenticatedPrincipalRef, Error> {
        AuthenticatedPrincipalRef::new(self.array()?).ok_or(Error::Malformed)
    }
    pub fn binding(&mut self) -> Result<GrantBinding, Error> {
        let b = GrantBinding {
            principal: self.principal()?,
            locator: self.locator()?,
            frontend: self.frontend()?,
            owner: OwnerInstance::new(self.array()?).ok_or(Error::Malformed)?,
            expires_at_monotonic: self.u64()?,
        };
        b.validate()?;
        Ok(b)
    }
    pub fn finish(self) -> Result<(), Error> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }
}
pub(super) fn put_locator(out: &mut Vec<u8>, v: SessionLocator) {
    out.extend_from_slice(v.session.as_bytes());
    out.extend_from_slice(v.owner.as_bytes());
}
pub(super) fn put_attachment(out: &mut Vec<u8>, v: Attachment) {
    put_locator(out, v.locator);
    out.extend_from_slice(v.frontend.as_bytes());
    out.extend_from_slice(&v.epoch.get().to_be_bytes());
}
pub(super) fn put_binding(out: &mut Vec<u8>, v: GrantBinding) {
    out.extend_from_slice(v.principal.as_bytes());
    put_locator(out, v.locator);
    out.extend_from_slice(v.frontend.as_bytes());
    out.extend_from_slice(v.owner.as_bytes());
    out.extend_from_slice(&v.expires_at_monotonic.to_be_bytes());
}
