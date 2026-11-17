//! Dormant System destination identity; no real monitor producer exists yet.
use crate::session_owner::host_engine::LocalBinding;
use std::sync::Arc;

/// Opaque exact System destination. Only a future retained monitor owner may
/// produce this capability. There is deliberately no production constructor.
/// This is identity custody, never a PAM, wait, or resource completion receipt.
pub(crate) struct DurableMonitorDestination {
    binding: Arc<LocalBinding>,
    monitor: super::MonitorOwner,
    identity: Arc<()>,
}
impl DurableMonitorDestination {
    pub(crate) fn matches(&self, binding: &Arc<LocalBinding>) -> bool {
        Arc::ptr_eq(&self.binding, binding)
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
    use std::sync::Arc;

    #[tokio::test]
    async fn linux529_system_destination_refusal_returns_exact_identity_and_same_login_incarnations_stay_distinct(
    ) {
        let (host, owner, frontend, attempt, attachment, _restart) = attached(HostMode::System);
        let (foreign_host, foreign_owner, _, _, _, _foreign_restart) = attached(HostMode::System);
        let first = DurableMonitorDestination {
            binding: destination_binding(&owner),
            monitor: super::super::MonitorOwner {
                login: [71; 16],
                incarnation: 1,
            },
            identity: Arc::new(()),
        };
        let second = DurableMonitorDestination {
            binding: destination_binding(&owner),
            monitor: super::super::MonitorOwner {
                login: [71; 16],
                incarnation: 2,
            },
            identity: Arc::new(()),
        };
        assert_ne!(first.monitor, second.monitor);
        assert!(!Arc::ptr_eq(&first.identity, &second.identity));
        let identity = first.identity.clone();
        let refused = match LinuxOwnerRoute::bind_system(
            &foreign_host,
            &foreign_owner,
            frontend,
            attempt,
            attachment,
            first,
        ) {
            Ok(_) => panic!("foreign destination admitted"),
            Err(refused) => refused,
        };
        let (_, returned) = refused.into_parts();
        assert!(Arc::ptr_eq(&identity, &returned.identity));
        assert_eq!(returned.monitor.incarnation, 1);
        let mut route =
            LinuxOwnerRoute::bind_system(&host, &owner, frontend, attempt, attachment, returned)
                .unwrap_or_else(|_| panic!("exact destination refused"));
        let mut wrong_owner = foreign_owner;
        let mut wrong_host = foreign_host;
        assert!(route
            .begin_detach(&mut wrong_host, &mut wrong_owner)
            .is_err());
        assert_eq!(wrong_host.catalog_len(), 1);
        let foreign_destination = DurableMonitorDestination {
            binding: destination_binding(&wrong_owner),
            monitor: second.monitor,
            identity: Arc::new(()),
        };
        assert!(LinuxOwnerRoute::bind_system(
            &host,
            &owner,
            frontend,
            attempt,
            attachment,
            foreign_destination
        )
        .is_err());
        assert!(
            LinuxOwnerRoute::bind_system(&host, &owner, frontend, attempt, attachment, second)
                .is_ok()
        );
        assert_eq!(host.catalog_len(), 1);
    }
    #[test]
    fn linux529_system_destination_cannot_authorize_personal_mode() {
        let (host, owner, frontend, attempt, attachment, _restart) = attached(HostMode::Personal {
            canonical_uid: 1000,
        });
        let destination = DurableMonitorDestination {
            binding: destination_binding(&owner),
            monitor: super::super::MonitorOwner {
                login: [71; 16],
                incarnation: 3,
            },
            identity: Arc::new(()),
        };
        let identity = destination.identity.clone();
        let refused = match LinuxOwnerRoute::bind_system(
            &host,
            &owner,
            frontend,
            attempt,
            attachment,
            destination,
        ) {
            Ok(_) => panic!("System route authorized Personal mode"),
            Err(refused) => refused,
        };
        let (_, returned) = refused.into_parts();
        assert!(Arc::ptr_eq(&identity, &returned.identity));
        assert_eq!(returned.monitor.incarnation, 3);
        assert_eq!(host.catalog_len(), 1);
    }
}
