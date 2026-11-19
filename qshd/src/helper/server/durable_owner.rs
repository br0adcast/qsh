//! Dormant System destination identity; no real monitor producer exists yet.
//! Weak identity is only correlation for retained local engine cleanup. Before
//! any monitor I/O, the real helper lifecycle must supply retained monitor
//! operation custody; this boundary provides no control endpoint or wait proof.
use crate::session_owner::host_engine::LocalBinding;
use std::sync::{Arc, Weak};

struct MonitorIdentity {
    binding: Arc<LocalBinding>,
    monitor: super::MonitorOwner,
}
/// The helper alone retains admission authority for one exact monitor binding.
/// There is no production constructor until actual durable custody exists.
pub(crate) struct DurableMonitorBinding {
    identity: Arc<MonitorIdentity>,
}
/// Non-owning destination correlation cannot keep retired admission alive.
/// This never represents PAM, native wait, or resource completion.
pub(crate) struct DurableMonitorDestination {
    identity: Weak<MonitorIdentity>,
}
impl DurableMonitorDestination {
    pub(crate) fn matches_expected(
        &self,
        expected: &DurableMonitorBinding,
        binding: &Arc<LocalBinding>,
    ) -> bool {
        self.identity.upgrade().is_some_and(|actual| {
            Arc::ptr_eq(&actual, &expected.identity) && Arc::ptr_eq(&actual.binding, binding)
        })
    }
    pub(crate) fn matches_live(&self, binding: &Arc<LocalBinding>) -> bool {
        self.identity
            .upgrade()
            .is_some_and(|actual| Arc::ptr_eq(&actual.binding, binding))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_owner::authorization::HostMode;
    use crate::session_owner::linux::{
        tests::{attached, destination_binding},
        LinuxOwnerRoute,
    };

    // Modeled identity only: no real monitor, PAM handle, child or wait proof.
    fn binding(
        owner: &crate::session_owner::host_engine::LocalOwnerEngine,
        incarnation: u64,
    ) -> DurableMonitorBinding {
        DurableMonitorBinding {
            identity: Arc::new(MonitorIdentity {
                binding: destination_binding(owner),
                monitor: super::super::MonitorOwner {
                    login: [71; 16],
                    incarnation,
                },
            }),
        }
    }
    fn destination(binding: &DurableMonitorBinding) -> DurableMonitorDestination {
        DurableMonitorDestination {
            identity: Arc::downgrade(&binding.identity),
        }
    }
    #[tokio::test]
    async fn linux529_system_wrong_incarnation_and_retired_binding_refuse_without_retargeting() {
        let (mut host, mut owner, frontend, attempt, attachment, _restart) =
            attached(HostMode::System);
        let expected = binding(&owner, 1);
        let successor = binding(&owner, 2);
        assert_eq!(
            expected.identity.monitor.login,
            successor.identity.monitor.login
        );
        let supplied = destination(&successor);
        let original = supplied.identity.clone();
        let refused = match LinuxOwnerRoute::bind_system(
            &host, &owner, frontend, attempt, attachment, &expected, supplied,
        ) {
            Ok(_) => panic!("different monitor incarnation admitted for expected binding"),
            Err(refused) => refused,
        };
        let (_, returned) = refused.into_parts();
        assert!(std::sync::Weak::ptr_eq(&original, &returned.identity));
        let duplicate = binding(&owner, 1);
        assert!(
            LinuxOwnerRoute::bind_system(
                &host,
                &owner,
                frontend,
                attempt,
                attachment,
                &expected,
                destination(&duplicate)
            )
            .is_err(),
            "equal visible fields are not the same retained identity"
        );
        let mut stale = LinuxOwnerRoute::bind_system(
            &host,
            &owner,
            frontend,
            attempt,
            attachment,
            &expected,
            destination(&expected),
        )
        .unwrap_or_else(|_| panic!("exact binding refused"));
        drop(expected);
        assert!(stale.begin_detach(&mut host, &mut owner).is_err());
        assert!(stale.begin_terminate(&mut host, &mut owner).is_err());
        let mut current = LinuxOwnerRoute::bind_system(
            &host, &owner, frontend, attempt, attachment, &successor, returned,
        )
        .unwrap_or_else(|_| panic!("successor binding refused"));
        current.begin_detach(&mut host, &mut owner).unwrap();
        drop(successor);
        current.finish_detach(&mut host, &mut owner).await.unwrap();
        assert_eq!(
            host.catalog_len(),
            1,
            "detaching a modeled destination cannot complete the owner"
        );
    }
    #[tokio::test]
    async fn linux529_system_admitted_termination_keeps_cleanup_after_expected_binding_drops() {
        let (mut host, mut owner, frontend, attempt, attachment, _restart) =
            attached(HostMode::System);
        let expected = binding(&owner, 1);
        let mut route = LinuxOwnerRoute::bind_system(
            &host,
            &owner,
            frontend,
            attempt,
            attachment,
            &expected,
            destination(&expected),
        )
        .unwrap_or_else(|_| panic!("exact binding refused"));
        route.begin_terminate(&mut host, &mut owner).unwrap();
        drop(expected);
        route
            .finish_terminate(&mut host, &mut owner, 7)
            .await
            .unwrap();
        assert_eq!(host.catalog_len(), 0);
    }
    #[test]
    fn linux529_system_destination_wrong_host_and_mode_return_original_identity() {
        let (host, owner, frontend, attempt, attachment, _restart) = attached(HostMode::System);
        let (foreign, foreign_owner, _, _, _, _foreign_restart) = attached(HostMode::System);
        let expected = binding(&owner, 1);
        let supplied = destination(&expected);
        let original = supplied.identity.clone();
        let refused = match LinuxOwnerRoute::bind_system(
            &foreign,
            &foreign_owner,
            frontend,
            attempt,
            attachment,
            &expected,
            supplied,
        ) {
            Ok(_) => panic!("foreign destination admitted"),
            Err(refused) => refused,
        };
        let (_, returned) = refused.into_parts();
        assert!(std::sync::Weak::ptr_eq(&original, &returned.identity));
        assert!(LinuxOwnerRoute::bind_system(
            &host,
            &owner,
            frontend,
            attempt,
            attachment,
            &binding(&foreign_owner, 1),
            returned
        )
        .is_err());
        let (personal, owner, frontend, attempt, attachment, _restart) =
            attached(HostMode::Personal {
                canonical_uid: 1000,
            });
        let expected = binding(&owner, 1);
        assert!(LinuxOwnerRoute::bind_system(
            &personal,
            &owner,
            frontend,
            attempt,
            attachment,
            &expected,
            destination(&expected)
        )
        .is_err());
        assert_eq!(host.catalog_len(), 1);
        assert_eq!(personal.catalog_len(), 1);
    }
}
