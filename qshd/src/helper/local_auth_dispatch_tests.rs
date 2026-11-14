// Real admitted socket custody; no decoded peer or synthetic successful policy.
#[cfg(target_os = "linux")]
mod system_dispatch {
    use super::*;
    use crate::session_owner::authorization::HostMode;
    use crate::session_owner::host::{HostLimits, HostState};
    use crate::session_owner::local_channel::{
        admit_channel, provision_pair, AdmissionBudget, TrustedChannelConfig,
    };
    use crate::session_owner::protocol::OwnerRole;
    use crate::session_owner::resource_contract::{ByteLimits, ResourceLimits, ScreenLimits};
    use super::super::local_auth_dispatch::{Step, SystemHelperDispatch};

    fn global_host() -> HostState { global_host_mode(HostMode::System) }
    fn global_host_mode(mode: HostMode) -> HostState {
        let bytes = ByteLimits { channel_bytes: 1024, session_bytes: 2048,
            account_bytes: 4096, global_bytes: 8192 };
        HostState::new(mode, HostLimits::new(ResourceLimits {
            max_reservations: 128,
            screen: ScreenLimits::from_existing(crate::screen_budget::BudgetLimits::default()).unwrap(),
            snapshot_transfer: bytes, control_queue: bytes,
        }, 4, 4, 4, 4, 1000).unwrap()).unwrap()
    }

    fn isolated(body: &str) {
        let name = format!("helper::server::tests::system_dispatch::{body}");
        let (status, stdout, stderr) = super::super::super::spawner::tests::run_isolated(&name);
        assert!(status.success(), "isolated System bridge {body}: {status}\n{stdout}\n{stderr}");
    }

    #[test]
    fn authdispatch529_system_eof_retires_real_admitted_frontend() {
        isolated("eof_body");
    }

    #[test]
    #[ignore = "isolated single-threaded helper fixture"]
    fn eof_body() {
        let mut host = global_host();
        let budget = AdmissionBudget::new(1).unwrap();
        let config = TrustedChannelConfig { host: host.instance(), owner: None,
            requester: OwnerRole::Frontend, mode: HostMode::System,
            system_uid: nix::unistd::geteuid().as_raw(), min_version: 1, max_version: 1 };
        let (a, b) = provision_pair(config, &budget).unwrap();
        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        let frontend = std::thread::spawn(move || admit_channel(a, deadline));
        let channel = admit_channel(b, deadline).unwrap();
        let frontend = frontend.join().unwrap().unwrap();
        let dispatch = channel.into_host_dispatch(&mut host, HostMode::System, 4).unwrap();
        let registration = dispatch.frontend();
        let mut bridge = SystemHelperDispatch::bind(dispatch, &host, 1000, 1000).unwrap();
        let mut state = empty_state();
        let seams = DirectSeam::new();
        drop(frontend);
        assert_eq!(bridge.step(seams.seams(), &mut state, &mut host, &test_config(), UNPRIVILEGED, 0).unwrap(), Step::Closed);
        assert!(host.begin_authentication(registration, 1, 10).is_err());
        assert_eq!(budget.in_use(), 0);
        assert_eq!(host.catalog_len(), 0);
        assert!(state.pending.is_empty());
        assert!(state.logins.is_empty());
    }

    use crate::session_owner::host_auth_contract::{AuthMethod,AuthOutcome,AuthReference,AuthRefusal,HostAuthMessage};
    use crate::session_owner::host_protocol::{self,HostDecoder,HostFrame,HostHeader,HostMessage};
    use crate::session_owner::local_channel::AdmittedChannel;
    use std::collections::VecDeque;

    // Ephemeral signed-v2 keys authorize only disposable test authorized_keys.
    fn make_key()->PrivateKey {
        PrivateKey::random(&mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),Algorithm::Ed25519).unwrap()
    }
    fn signed(key:&PrivateKey,nonce:Nonce)->transport::AuthRecord {
        let Request::Verify{login,public_key,signature,nonce,..}=proof_for_login(key,&my_login(),[7;32],nonce,[9;16]) else{unreachable!()};
        transport::AuthRecord{public_key,signature,v2:Some(AuthV2{login,nonce})}
    }
    fn pair(host:&mut HostState,budget:&AdmissionBudget,mode:HostMode)->(AdmittedChannel,SystemHelperDispatch){
        let cfg=TrustedChannelConfig{host:host.instance(),owner:None,requester:OwnerRole::Frontend,mode,system_uid:nix::unistd::geteuid().as_raw(),min_version:1,max_version:1};
        let(a,b)=provision_pair(cfg,budget).unwrap();let until=Instant::now()+TEST_RECV_TIMEOUT;
        let worker=std::thread::spawn(move||admit_channel(a,until));let channel=admit_channel(b,until);let frontend=worker.join().unwrap().unwrap();
        let dispatch=channel.unwrap().into_host_dispatch(host,mode,4).unwrap();
        (frontend,SystemHelperDispatch::bind(dispatch,host,10_000,10_000).unwrap())
    }
    struct Fixture {
        _dir:tempfile::TempDir,
        key:PrivateKey,
        config:HelperConfig,
        host:HostState,
        state:LoopState,
        seams:DirectSeam,
        front:Option<AdmittedChannel>,
        bridge:SystemHelperDispatch,
        budget:AdmissionBudget,
        replies:VecDeque<HostFrame>,
        decoder:HostDecoder,
        request:u64,
        clock:u64,
    }
    impl Fixture {
        fn new()->Self{
            let dir=tempfile::tempdir().unwrap();let key=make_key();let config=trusting_config(dir.path(),&key);
            let mut host=global_host();let budget=AdmissionBudget::new(4).unwrap();let(front,bridge)=pair(&mut host,&budget,HostMode::System);
            Self{_dir:dir,key,config,host,state:empty_state(),seams:DirectSeam::new(),front:Some(front),bridge,budget,replies:VecDeque::new(),decoder:HostDecoder::new(),request:1,clock:0}
        }
        fn step(&mut self)->Result<Step,super::super::local_auth_dispatch::BridgeError>{
            self.clock+=1;self.bridge.step(self.seams.seams(),&mut self.state,&mut self.host,&self.config,UNPRIVILEGED,self.clock)
        }
        fn raw(&mut self,bytes:&[u8]){
            let until=Instant::now()+TEST_RECV_TIMEOUT;let mut at=0;
            while at<bytes.len(){assert!(Instant::now()<until);match self.front.as_mut().unwrap().frontend_write(self.host.instance(),HostMode::System,&bytes[at..]){Ok(n)=>{assert!(n>0);at+=n},Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{self.step().unwrap();std::thread::sleep(Duration::from_millis(1));},Err(e)=>panic!("frontend write: {e}")}}
        }
        fn send(&mut self,message:HostAuthMessage)->u64{
            self.request+=1;let id=self.request;let bytes=host_protocol::encode(&HostFrame{header:HostHeader{role:OwnerRole::Frontend,host:self.host.instance(),request_id:id},message:HostMessage::Authentication(message)}).unwrap();self.raw(&bytes);id
        }
        fn coalesce(&mut self, messages: &[HostAuthMessage]) -> Vec<u64> {
            let mut bytes = Vec::new();
            let mut ids = Vec::new();
            for message in messages {
                self.request += 1;
                ids.push(self.request);
                bytes.extend(host_protocol::encode(&HostFrame {
                    header: HostHeader { role: OwnerRole::Frontend, host: self.host.instance(), request_id: self.request },
                    message: HostMessage::Authentication(message.clone()),
                }).unwrap());
            }
            assert!(bytes.len() <= 4096);
            assert_eq!(self.front.as_mut().unwrap().frontend_write(self.host.instance(), HostMode::System, &bytes).unwrap(), bytes.len(), "whole coalesced batch admitted before bridge progress");
            ids
        }
        fn receive(&mut self)->HostFrame{
            let until=Instant::now()+TEST_RECV_TIMEOUT;
            loop{
                if let Some(frame)=self.replies.pop_front(){return frame}
                assert!(Instant::now()<until,"bounded actual System proof response");self.step().unwrap();
                let mut bytes=[0;4096];match self.front.as_mut().unwrap().frontend_read(self.host.instance(),HostMode::System,&mut bytes){Ok(0)=>panic!("unexpected channel EOF"),Ok(n)=>self.replies.extend(self.decoder.push(&bytes[..n]).unwrap()),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>std::thread::sleep(Duration::from_millis(1)),Err(e)=>panic!("frontend read: {e}")}
            }
        }
        fn begin(&mut self)->(AuthReference,Nonce){
            self.send(HostAuthMessage::Begin{method:AuthMethod::System});
            match self.receive().message {HostMessage::Authentication(HostAuthMessage::Challenge{method:AuthMethod::System,ticket,nonce:Some(nonce),..})=>(ticket,nonce),other=>panic!("expected real challenge: {other:?}")}
        }
        fn submit(&mut self,ticket:AuthReference,record:transport::AuthRecord){self.send(HostAuthMessage::SystemProof{ticket,handshake_hash:[7;32],record});self.step().unwrap();}
        fn outcome(&mut self)->AuthOutcome{match self.receive().message{HostMessage::Authentication(HostAuthMessage::Result{outcome,..})=>outcome,other=>panic!("expected real result: {other:?}")}}
        fn finish(self){let Fixture{_dir,mut state,mut host,seams,front,bridge,budget,..}=self;bridge.close(&mut state,&mut host);drop(front);seams.settle(&mut state,&test_config());assert!(state.pending.is_empty());assert!(state.host_auth_tickets.is_empty());assert!(state.host_nonces.is_empty());assert!(state.logins.is_empty());assert!(state.verified.is_empty());assert_eq!(budget.in_use(),0);}
    }
    #[test] fn authdispatch529_system_real_signed_proof_and_current_revocation(){isolated("real_policy_body");}
    #[test] #[ignore="isolated single-threaded helper fixture"]
    fn real_policy_body(){
        let mut f=Fixture::new();let(ticket,nonce)=f.begin();assert_eq!(f.state.host_auth_tickets.len(),1);assert_eq!(f.state.host_nonces.len(),1);f.submit(ticket,signed(&f.key,nonce));assert_eq!(f.state.pending.verifying(),1);
        let mut pin=helper40_pin_verification(&mut f.state);let AuthOutcome::Accepted(context)=f.outcome() else{panic!("real signed proof must authenticate")};assert_ne!(context,ticket);f.seams.settle(&mut f.state,&f.config);assert!(matches!(pin.observe(&mut crate::process_scope::Native),crate::process_scope::Evidence::Exited));
        f.clock += 10_001;
        assert_ne!(f.step().unwrap(), Step::Closed, "accepted authentication survives Begin deadline");
        super::super::local_auth_dispatch::assertions::current_revocation(&mut f.bridge,&mut f.state,&mut f.host,f.seams.seams(),&f.config,UNPRIVILEGED,&mut f.clock);
        assert_eq!(f.host.catalog_len(),1);f.finish();
    }
    #[test]
    fn authdispatch529_system_coalesced_requests_keep_ordered_replies() {
        isolated("coalesced_body");
    }
    #[test]
    #[ignore = "isolated single-threaded helper fixture"]
    fn coalesced_body() {
        let mut f = Fixture::new();
        let sentinel = [0x61; 16];
        f.state.nonces.insert(sentinel, Instant::now());
        let begin = HostAuthMessage::Begin { method: AuthMethod::System };
        let ids = f.coalesce(&[begin.clone(), begin.clone()]);
        let first = f.receive();
        assert_eq!(first.header.request_id, ids[0]);
        let HostMessage::Authentication(HostAuthMessage::Challenge { ticket, nonce: Some(nonce), .. }) = first.message else { panic!("first coalesced Begin must receive Challenge") };
        let second = f.receive();
        assert_eq!(second.header.request_id, ids[1]);
        assert!(matches!(second.message, HostMessage::Authentication(HostAuthMessage::ChallengeRefused { method: AuthMethod::System, reason: AuthRefusal::Unavailable })));
        assert_eq!(f.state.host_auth_tickets.len(), 1);
        assert_eq!(f.state.host_nonces.len(), 1);
        assert!(f.state.host_nonces.contains_key(&nonce));
        let cancel = f.send(HostAuthMessage::Cancel { ticket });
        let reply = f.receive();
        assert_eq!(reply.header.request_id, cancel);
        assert!(matches!(reply.message, HostMessage::Authentication(HostAuthMessage::Cancelled { ticket: t }) if t == ticket));
        assert!(f.state.host_nonces.is_empty());
        assert!(f.state.nonces.contains_key(&sentinel));
        let (old, old_nonce) = f.begin();
        let ids = f.coalesce(&[HostAuthMessage::Cancel { ticket: old }, begin]);
        let first = f.receive();
        assert_eq!(first.header.request_id, ids[0]);
        assert!(matches!(first.message, HostMessage::Authentication(HostAuthMessage::Cancelled { ticket }) if ticket == old));
        let second = f.receive();
        assert_eq!(second.header.request_id, ids[1]);
        let HostMessage::Authentication(HostAuthMessage::Challenge { ticket: fresh, nonce: Some(fresh_nonce), .. }) = second.message else { panic!("Cancel/Begin must receive fresh Challenge") };
        assert_ne!(fresh, old);
        assert!(!f.state.host_nonces.contains_key(&old_nonce));
        assert!(f.state.host_nonces.contains_key(&fresh_nonce));
        assert_eq!(f.state.host_auth_tickets.len(), 1);
        let cancel = f.send(HostAuthMessage::Cancel { ticket: fresh });
        let reply = f.receive();
        assert_eq!(reply.header.request_id, cancel);
        assert!(matches!(reply.message, HostMessage::Authentication(HostAuthMessage::Cancelled { ticket }) if ticket == fresh));
        assert!(f.state.host_nonces.is_empty());
        assert!(f.state.pending.is_empty());
        assert!(f.state.logins.is_empty());
        assert_eq!(f.host.catalog_len(), 0);
        assert!(f.state.nonces.contains_key(&sentinel));
        f.finish();
        coalesced_boundaries();
    }
    fn coalesced_boundaries() {
        use super::super::local_auth_dispatch::assertions;
        use crate::session_owner::protocol::MAX_OWNER_REQUESTS;
        let begin = HostAuthMessage::Begin { method: AuthMethod::System };
        let mut f = Fixture::new();
        f.begin();
        f.request += 1;
        assertions::queue_state(&mut f.bridge, f.request, f.clock);
        assert_eq!(f.state.host_nonces.len(), 1);
        assert_eq!(f.state.host_auth_tickets.len(), 1);
        f.finish();

        // The single chunk covers the exact window and one-over with/without
        // an already submitted real proof's reserved asynchronous reply.
        for (debt, count, admitted) in [(false, MAX_OWNER_REQUESTS, true),
            (false, MAX_OWNER_REQUESTS + 1, false),
            (true, MAX_OWNER_REQUESTS - 1, true), (true, MAX_OWNER_REQUESTS, false)] {
            let mut f = Fixture::new();
            let sentinel = [0x62; 16];
            f.state.nonces.insert(sentinel, Instant::now());
            let mut ticket = None;
            if debt {
                let (t, nonce) = f.begin();
                ticket = Some(t);
                f.submit(t, signed(&f.key, nonce));
                f.seams.settle(&mut f.state, &f.config);
                assertions::proof_debt_boundaries(&f.bridge);
            }
            let proof_id = f.request;
            let ids = f.coalesce(&vec![begin.clone(); count]);
            if admitted {
                for (i, id) in ids.iter().enumerate() {
                    let reply = f.receive();
                    assert_eq!(reply.header.request_id, *id);
                    if !debt && i == 0 {
                        let HostMessage::Authentication(HostAuthMessage::Challenge { ticket: t, .. }) = reply.message else { panic!("first Begin owns the one registration") };
                        ticket = Some(t);
                    } else {
                        assert!(matches!(reply.message, HostMessage::Authentication(HostAuthMessage::ChallengeRefused { reason: AuthRefusal::Unavailable, .. })));
                    }
                    if debt && i == 0 {
                        assertions::ready_proof_deferred(&mut f.bridge, &mut f.state, &mut f.host, f.clock);
                    }
                }
                if debt {
                    let reply = f.receive();
                    assert_eq!(reply.header.request_id, proof_id);
                    assert!(matches!(reply.message, HostMessage::Authentication(HostAuthMessage::Result { outcome: AuthOutcome::Accepted(_), .. })));
                }
                let ticket = ticket.unwrap();
                let id = f.send(HostAuthMessage::Cancel { ticket });
                let reply = f.receive();
                assert_eq!(reply.header.request_id, id);
                assert!(matches!(reply.message, HostMessage::Authentication(HostAuthMessage::Cancelled { ticket: t }) if t == ticket));
            } else {
                assert!(matches!(f.step(), Err(super::super::local_auth_dispatch::BridgeError::Refused)), "over-window batch must fail before admitting new requests");
                assert_eq!(f.step().unwrap(), Step::Closed);
            }
            assert!(f.state.nonces.contains_key(&sentinel));
            assert!(f.state.host_auth_tickets.is_empty());
            assert!(f.state.host_nonces.is_empty());
            assert!(f.state.pending.is_empty());
            assert!(f.state.logins.is_empty());
            assert_eq!(f.host.catalog_len(), 0);
            f.finish();
        }

        let mut f = Fixture::new();
        assertions::short_output_timeout(&mut f.bridge);
        f.coalesce(&[begin.clone(), begin.clone()]);
        assert!(matches!(f.receive().message, HostMessage::Authentication(HostAuthMessage::Challenge { .. })));
        let deadline = assertions::queued(&f.bridge, 1);
        assert_eq!(deadline, f.clock + 2);
        f.clock = deadline - 1;
        assert_eq!(f.step().unwrap(), Step::Closed, "second reply retains its enqueue deadline after first drains");
        assertions::retired(&f.bridge);
        assert!(f.state.host_auth_tickets.is_empty());
        assert!(f.state.host_nonces.is_empty());
        assert!(f.state.pending.is_empty());
        f.finish();

        let mut f = Fixture::new();
        let (ticket, nonce) = f.begin();
        let proof_deadline = f.clock + 10_000;
        f.submit(ticket, signed(&f.key, nonce));
        f.seams.settle(&mut f.state, &f.config);
        f.coalesce(&[begin.clone(), begin.clone()]);
        assert!(matches!(f.receive().message, HostMessage::Authentication(HostAuthMessage::ChallengeRefused { .. })));
        assertions::ready_proof_deferred(&mut f.bridge, &mut f.state, &mut f.host, f.clock);
        assertions::queued(&f.bridge, 1);
        f.clock = proof_deadline - 1;
        assert_eq!(f.step().unwrap(), Step::Closed, "ready proof held by backpressure still expires rather than becoming a late acceptance");
        assertions::retired(&f.bridge);
        assert_eq!(f.host.catalog_len(), 0);
        assert!(f.state.pending.is_empty());
        f.finish();

        let mut f = Fixture::new();
        let (ticket, nonce) = f.begin();
        f.submit(ticket, signed(&f.key, nonce));
        assert!(matches!(f.outcome(), AuthOutcome::Accepted(_)));
        f.seams.settle(&mut f.state, &f.config);
        f.coalesce(&[begin.clone(), begin.clone(), begin]);
        assert!(matches!(f.receive().message, HostMessage::Authentication(HostAuthMessage::ChallengeRefused { .. })));
        assertions::queued(&f.bridge, 2);
        f.clock += 1;
        assertions::start_queued_current(&mut f.bridge, &mut f.state, &mut f.host, &f.config, UNPRIVILEGED, f.clock);
        f.seams.settle(&mut f.state, &f.config);
        f.step().unwrap();
        assertions::queued(&f.bridge, 1);
        assertions::queued_current_completed(&f.bridge);
        f.finish();
    }
    #[test] fn authdispatch529_system_forged_signature_and_unlisted_key_refuse(){isolated("forged_body");}
    #[test] #[ignore="isolated single-threaded helper fixture"]
    fn forged_body(){for bad_key in [false,true]{let mut f=Fixture::new();let(ticket,nonce)=f.begin();let mut proof=if bad_key{signed(&make_key(),nonce)}else{signed(&f.key,nonce)};if !bad_key{proof.signature[0]^=1;}f.submit(ticket,proof);assert!(matches!(f.outcome(),AuthOutcome::Refused(_)));assert_eq!(f.host.catalog_len(),0);f.finish();}}
    #[test] fn authdispatch529_system_cancel_unsubmitted_cleans_only_exact_nonce(){isolated("cancel_unsubmitted_body");}
    #[test] #[ignore="isolated single-threaded helper fixture"]
    fn cancel_unsubmitted_body(){let mut f=Fixture::new();let sentinel=[0x51;16];f.state.nonces.insert(sentinel,Instant::now());let(ticket,_)=f.begin();f.send(HostAuthMessage::Cancel{ticket});assert!(matches!(f.receive().message,HostMessage::Authentication(HostAuthMessage::Cancelled{..})));assert!(f.state.host_nonces.is_empty());assert!(f.state.host_auth_tickets.is_empty());assert!(f.state.nonces.contains_key(&sentinel));let(_,_) =f.begin();f.finish();}
    #[test] fn authdispatch529_system_cancel_submitted_retains_real_child_until_wait(){isolated("cancel_submitted_body");}
    #[test] #[ignore="isolated single-threaded helper fixture"]
    fn cancel_submitted_body(){let mut f=Fixture::new();f.config.verify_timeout=Duration::from_millis(80);let(ticket,nonce)=f.begin();f.send(HostAuthMessage::SystemProof{ticket,handshake_hash:[7;32],record:signed(&f.key,nonce)});f.clock+=1;f.bridge.step(f.seams.seams(),&mut f.state,&mut f.host,&f.config,AccountSwitches{read_keys:read_keys_that_never_finishes,..UNPRIVILEGED},f.clock).unwrap();let mut pin=helper40_pin_verification(&mut f.state);f.send(HostAuthMessage::Cancel{ticket});assert!(matches!(f.receive().message,HostMessage::Authentication(HostAuthMessage::Cancelled{..})));if f.state.pending.verifying()==0 {assert!(matches!(pin.observe(&mut crate::process_scope::Native),crate::process_scope::Evidence::Exited));} else {assert_eq!(f.state.pending.verifying(),1);}f.seams.settle(&mut f.state,&f.config);assert!(matches!(pin.observe(&mut crate::process_scope::Native),crate::process_scope::Evidence::Exited));f.finish();}
    #[test] fn authdispatch529_system_eof_submitted_drops_sink_not_physical_custody(){isolated("eof_submitted_body");}
    #[test] #[ignore="isolated single-threaded helper fixture"]
    fn eof_submitted_body(){let mut f=Fixture::new();f.config.verify_timeout=Duration::from_millis(80);let(ticket,nonce)=f.begin();f.send(HostAuthMessage::SystemProof{ticket,handshake_hash:[7;32],record:signed(&f.key,nonce)});f.clock+=1;f.bridge.step(f.seams.seams(),&mut f.state,&mut f.host,&f.config,AccountSwitches{read_keys:read_keys_that_never_finishes,..UNPRIVILEGED},f.clock).unwrap();let mut pin=helper40_pin_verification(&mut f.state);drop(f.front.take());assert_eq!(f.step().unwrap(),Step::Closed);if f.state.pending.verifying()==0 {assert!(matches!(pin.observe(&mut crate::process_scope::Native),crate::process_scope::Evidence::Exited));} else {assert_eq!(f.state.pending.verifying(),1);}f.seams.settle(&mut f.state,&f.config);assert!(matches!(pin.observe(&mut crate::process_scope::Native),crate::process_scope::Evidence::Exited));f.finish();}
    #[test] fn authdispatch529_system_global_nonce_saturation_is_shared(){isolated("nonce_cap_body");}
    #[test] #[ignore="isolated single-threaded helper fixture"]
    fn nonce_cap_body(){let mut f=Fixture::new();for i in 0..MAX_OUTSTANDING_NONCES {let mut nonce=[0;16];nonce[..8].copy_from_slice(&(i as u64).to_be_bytes());f.state.nonces.insert(nonce,Instant::now());}f.send(HostAuthMessage::Begin{method:AuthMethod::System});assert!(matches!(f.receive().message,HostMessage::Authentication(HostAuthMessage::ChallengeRefused{..})));assert!(f.state.host_nonces.is_empty());assert!(f.state.host_auth_tickets.is_empty());f.state.nonces.clear();f.begin();f.finish();}
    #[test] fn authdispatch529_system_cap_before_spend_cleans_exact_remaining_nonce(){isolated("verifier_cap_body");}
    #[test] #[ignore="isolated single-threaded helper fixture"]
    fn verifier_cap_body(){let mut f=Fixture::new();let(ticket,nonce)=f.begin();let sentinel=[0x52;16];f.state.host_nonces.insert(sentinel,Instant::now());for _ in 0..MAX_VERIFYING {f.state.pending.insert(fake_verify_pending(Instant::now()+Duration::from_secs(30)));}f.submit(ticket,signed(&f.key,nonce));assert!(!f.state.host_nonces.contains_key(&nonce));assert!(f.state.host_nonces.contains_key(&sentinel));assert_eq!(f.state.pending.verifying(),MAX_VERIFYING);assert!(matches!(f.outcome(),AuthOutcome::Refused(_)));f.state.pending=PendingTable::default();f.state.host_nonces.remove(&sentinel);f.finish();}
    #[test] fn authdispatch529_system_replay_and_cross_seam_do_not_touch_other_ticket(){isolated("replay_body");}
    #[test] #[ignore="isolated single-threaded helper fixture"]
    fn replay_body(){let mut f=Fixture::new();let(ticket,nonce)=f.begin();let(mut front2,mut bridge2)=pair(&mut f.host,&f.budget,HostMode::System);let bytes=host_protocol::encode(&HostFrame{header:HostHeader{role:OwnerRole::Frontend,host:f.host.instance(),request_id:2},message:HostMessage::Authentication(HostAuthMessage::SystemProof{ticket,handshake_hash:[7;32],record:signed(&f.key,nonce)})}).unwrap();front2.frontend_write(f.host.instance(),HostMode::System,&bytes).unwrap();f.clock+=1;assert!(bridge2.step(f.seams.seams(),&mut f.state,&mut f.host,&f.config,UNPRIVILEGED,f.clock).is_err());assert!(f.state.host_nonces.contains_key(&nonce));bridge2.close(&mut f.state,&mut f.host);drop(front2);f.submit(ticket,signed(&f.key,nonce));assert!(matches!(f.outcome(),AuthOutcome::Accepted(_)));f.send(HostAuthMessage::SystemProof{ticket,handshake_hash:[7;32],record:signed(&f.key,nonce)});assert!(f.step().is_err());f.finish();}
    #[test] fn authdispatch529_system_wrong_method_report_and_host_refuse(){isolated("wrong_binding_body");}
    #[test] #[ignore="isolated single-threaded helper fixture"]
    fn wrong_binding_body(){let mut f=Fixture::new();let mut other=global_host();f.clock+=1;assert!(f.bridge.step(f.seams.seams(),&mut f.state,&mut other,&f.config,UNPRIVILEGED,f.clock).is_err());assert_eq!(other.catalog_len(),0);let(ticket,_)=f.begin();f.send(HostAuthMessage::PersonalReport{ticket,key:[1;32],session_id:1,token:[2;16]});assert!(f.step().is_err());f.finish();let mut f=Fixture::new();f.send(HostAuthMessage::Begin{method:AuthMethod::Personal});assert!(f.step().is_err());f.finish();}
    #[test] fn authdispatch529_system_deadline_and_partial_input_expire_inert(){isolated("deadline_body");}
    #[test] #[ignore="isolated single-threaded helper fixture"]
    fn deadline_body(){let mut f=Fixture::new();f.begin();f.clock+=10_001;assert_eq!(f.step().unwrap(),Step::Closed);assert!(f.state.host_nonces.is_empty());f.finish();let mut f=Fixture::new();f.raw(b"QSHH");f.step().unwrap();f.clock+=10_001;assert_eq!(f.step().unwrap(),Step::Closed);assert!(f.state.pending.is_empty());f.finish();
        let mut f = Fixture::new();
        f.config.verify_timeout = Duration::from_millis(80);
        let (ticket, nonce) = f.begin();
        f.submit(ticket, signed(&f.key, nonce));
        assert!(matches!(f.outcome(), AuthOutcome::Accepted(_)));
        f.seams.settle(&mut f.state, &f.config);
        f.clock += 10_001;
        assert_ne!(f.step().unwrap(), Step::Closed);
        f.clock += 1;
        let attempt = super::super::local_auth_dispatch::assertions::expiring_current(
            &mut f.bridge, &mut f.state, &mut f.host, &f.config,
            AccountSwitches { read_keys: read_keys_that_never_finishes, ..UNPRIVILEGED }, f.clock);
        assert_eq!(f.state.pending.verifying(), 1);
        let mut pin = helper40_pin_verification(&mut f.state);
        f.clock += 1;
        assert_eq!(f.step().unwrap(), Step::Closed, "unfinished current policy keeps its own deadline after acceptance");
        assert_eq!(f.state.pending.verifying(), 1, "logical expiry cannot settle physical custody");
        assert!(f.host.create_session(attempt, f.clock).is_err());
        f.seams.settle(&mut f.state, &f.config);
        assert!(matches!(pin.observe(&mut crate::process_scope::Native), crate::process_scope::Evidence::Exited));
        f.finish();
    }

    #[test] fn authdispatch529_system_close_loses_sink_without_releasing_real_child(){isolated("close_debt_body");}
    #[test] #[ignore="isolated single-threaded helper fixture"]
    fn close_debt_body(){let mut f=Fixture::new();f.config.verify_timeout=Duration::from_millis(80);let(ticket,nonce)=f.begin();f.send(HostAuthMessage::SystemProof{ticket,handshake_hash:[7;32],record:signed(&f.key,nonce)});f.clock+=1;f.bridge.step(f.seams.seams(),&mut f.state,&mut f.host,&f.config,AccountSwitches{read_keys:read_keys_that_never_finishes,..UNPRIVILEGED},f.clock).unwrap();let mut pin=helper40_pin_verification(&mut f.state);let Fixture{_dir,mut state,mut host,seams,front,bridge,budget,config,..}=f;bridge.close(&mut state,&mut host);assert_eq!(state.pending.verifying(),1,"close performs no wait and cannot refund child custody");drop(front);seams.settle(&mut state,&config);assert!(state.pending.is_empty());assert!(matches!(pin.observe(&mut crate::process_scope::Native),crate::process_scope::Evidence::Exited));assert_eq!(budget.in_use(),0);assert!(state.logins.is_empty());}

    #[test] fn authdispatch529_system_full_sink_stale_real_result_cannot_approve_twin(){isolated("full_sink_body");}
    #[test] #[ignore="isolated single-threaded helper fixture"]
    fn full_sink_body(){let mut f=Fixture::new();let(ticket,nonce)=f.begin();f.submit(ticket,signed(&f.key,nonce));f.seams.settle(&mut f.state,&f.config);super::super::local_auth_dispatch::assertions::full_sink(f.front.as_mut().unwrap(),&mut f.bridge,&mut f.state,&mut f.host,f.seams.seams(),&f.config,UNPRIVILEGED,&mut f.clock,&f.key);f.finish();}
    #[test] fn authdispatch529_system_late_real_verdict_after_deadline_is_not_applied(){isolated("late_body");}
    #[test] #[ignore="isolated single-threaded helper fixture"]
    fn late_body(){let mut f=Fixture::new();let(ticket,nonce)=f.begin();f.submit(ticket,signed(&f.key,nonce));f.seams.settle(&mut f.state,&f.config);f.clock+=10_001;assert_eq!(f.step().unwrap(),Step::Closed);assert_eq!(f.host.catalog_len(),0);f.finish();}
    #[test] fn authdispatch529_system_current_policy_rejects_other_real_seam(){isolated("foreign_current_body");}
    #[test] #[ignore="isolated single-threaded helper fixture"]
    fn foreign_current_body(){let mut f=Fixture::new();let(t,n)=f.begin();f.submit(t,signed(&f.key,n));assert!(matches!(f.outcome(),AuthOutcome::Accepted(_)));let(mut other_front,mut other_bridge)=pair(&mut f.host,&f.budget,HostMode::System);std::mem::swap(f.front.as_mut().unwrap(),&mut other_front);std::mem::swap(&mut f.bridge,&mut other_bridge);let(t,n)=f.begin();f.submit(t,signed(&f.key,n));assert!(matches!(f.outcome(),AuthOutcome::Accepted(_)));std::mem::swap(f.front.as_mut().unwrap(),&mut other_front);std::mem::swap(&mut f.bridge,&mut other_bridge);super::super::local_auth_dispatch::assertions::foreign_current(&mut f.bridge,&mut other_bridge,&mut f.state,&mut f.host,&f.config,UNPRIVILEGED,&mut f.clock);other_bridge.close(&mut f.state,&mut f.host);drop(other_front);f.finish();}
    #[test] fn authdispatch529_system_host_pending_capacity_is_global(){isolated("host_cap_body");}
    #[test] #[ignore="isolated single-threaded helper fixture"]
    fn host_cap_body(){let mut f=Fixture::new();super::super::local_auth_dispatch::assertions::host_saturation(f.front.as_mut().unwrap(),&mut f.bridge,&mut f.state,&mut f.host,f.seams.seams(),&f.config,UNPRIVILEGED,&mut f.clock);f.finish();}
}
