//! Asked passwords and keyboard-interactive, against a russh server of our
//! own: the private sshd cannot take passwords without root.

mod support;

use std::sync::Arc;
use support::fake_server::{FakeAuth, FakeServer, HangUp};
use support::*;

fn fake_params(server: &FakeServer) -> ssh::SshParams {
    ssh::SshParams {
        host: "127.0.0.1".into(),
        port: server.port,
        username: "tester".into(),
        known_host_keys: vec![server.host_public_key_wire()],
        connect_timeout: std::time::Duration::from_secs(5),
        keepalive_interval: std::time::Duration::from_secs(15),
        compression: false,
        tcp_nodelay: true,
        knock: Vec::new(),
    }
}

fn go(
    params: ssh::SshParams,
    methods: Vec<ssh::AuthMethod>,
    prompter: Arc<CountingPrompter>,
) -> Result<(), ssh::SshError> {
    ssh::connect(
        params,
        ssh::SshAuthPlan { methods, prompter },
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    )
    .map(|(c, _)| c.close())
}

#[test]
fn an_asked_password_logs_in() {
    let server = FakeServer::start(FakeAuth {
        password: Some("s3cret".into()),
        ..FakeAuth::default()
    });
    let prompter = Arc::new(CountingPrompter::answering_password("s3cret"));
    go(
        fake_params(&server),
        vec![ssh::AuthMethod::AskPassword],
        Arc::clone(&prompter),
    )
    .expect("login");
    assert_eq!(prompter.password_asked(), 1);
}

#[test]
fn no_answer_to_the_password_is_a_refusal_naming_it() {
    let server = FakeServer::start(FakeAuth {
        password: Some("s3cret".into()),
        ..FakeAuth::default()
    });
    match go(
        fake_params(&server),
        vec![ssh::AuthMethod::AskPassword],
        Arc::new(CountingPrompter::default()),
    ) {
        Err(ssh::SshError::AuthFailed(r)) => assert!(r.contains("password: no answer"), "{r}"),
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

/// A server without password login is never asked about.
#[test]
fn a_server_without_passwords_is_not_asked_for_one() {
    let server = FakeServer::start(FakeAuth {
        kbd_rounds: vec![vec![("Code: ".into(), true, "42".into())]],
        ..FakeAuth::default()
    });
    let prompter = Arc::new(CountingPrompter::answering_password("x"));
    match go(
        fake_params(&server),
        vec![
            ssh::AuthMethod::Signer(Arc::new(SoftSigner::random())),
            ssh::AuthMethod::AskPassword,
        ],
        Arc::clone(&prompter),
    ) {
        Err(ssh::SshError::AuthFailed(r)) => {
            assert!(r.contains("publickey x1"), "{r}");
            assert!(!r.contains("password"), "{r}");
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
    assert_eq!(prompter.password_asked(), 0);
}

#[test]
fn keyboard_interactive_answers_every_round() {
    let server = FakeServer::start(FakeAuth {
        kbd_rounds: vec![
            vec![("Password: ".into(), false, "pw".into())],
            vec![("Code: ".into(), true, "123456".into())],
        ],
        ..FakeAuth::default()
    });
    let prompter = Arc::new(CountingPrompter::answering_kbd(&["pw", "123456"]));
    go(
        fake_params(&server),
        vec![ssh::AuthMethod::KeyboardInteractive],
        Arc::clone(&prompter),
    )
    .expect("login");
    assert_eq!(prompter.kbd_asked(), 2);
}

/// publickey, then keyboard-interactive: the second factor after a partial success.
#[test]
fn a_partial_success_goes_on_to_the_second_factor() {
    let signer = SoftSigner::random();
    let server = FakeServer::start(FakeAuth {
        partial_keys: vec![signer.public_wire()],
        kbd_rounds: vec![vec![("Code: ".into(), true, "7".into())]],
        ..FakeAuth::default()
    });
    let prompter = Arc::new(CountingPrompter::answering_kbd(&["7"]));
    go(
        fake_params(&server),
        vec![
            ssh::AuthMethod::Signer(Arc::new(signer)),
            ssh::AuthMethod::KeyboardInteractive,
        ],
        prompter,
    )
    .expect("login");
}

#[test]
fn a_slow_password_does_not_time_the_login_out() {
    let server = FakeServer::start(FakeAuth {
        password: Some("pw".into()),
        ..FakeAuth::default()
    });
    let mut p = fake_params(&server);
    p.connect_timeout = std::time::Duration::from_secs(1);
    let prompter = Arc::new(
        CountingPrompter::answering_password("pw").with_delay(std::time::Duration::from_secs(2)),
    );
    go(p, vec![ssh::AuthMethod::AskPassword], prompter).expect("login");
}

#[test]
fn a_slow_keyboard_interactive_answer_does_not_time_the_login_out() {
    let server = FakeServer::start(FakeAuth {
        kbd_rounds: vec![vec![("Code: ".into(), true, "42".into())]],
        ..FakeAuth::default()
    });
    let mut p = fake_params(&server);
    p.connect_timeout = std::time::Duration::from_secs(1);
    let prompter = Arc::new(
        CountingPrompter::answering_kbd(&["42"]).with_delay(std::time::Duration::from_secs(2)),
    );
    go(p, vec![ssh::AuthMethod::KeyboardInteractive], prompter).expect("login");
}

/// The connection drops in the middle of the login, with no word from the
/// server: that is a network matter the caller may retry, not a refusal.
#[test]
fn a_connection_lost_during_login_is_a_connection_error() {
    let server = FakeServer::start(FakeAuth {
        password: Some("pw".into()),
        hang_up: Some(HangUp::OnFirstAuth),
        ..FakeAuth::default()
    });
    match go(
        fake_params(&server),
        vec![ssh::AuthMethod::Password(ssh::Zeroizing::new("pw".into()))],
        Arc::new(CountingPrompter::default()),
    ) {
        Err(ssh::SshError::Connect(r)) => assert!(r.contains("lost during login"), "{r}"),
        other => panic!("expected Connect, got {other:?}"),
    }
}

/// A hang-up in the middle of keyboard-interactive is read the same way as
/// in any other method.
#[test]
fn a_keyboard_interactive_hang_up_is_a_connection_error_too() {
    let server = FakeServer::start(FakeAuth {
        kbd_rounds: vec![vec![("Code: ".into(), true, "42".into())]],
        hang_up: Some(HangUp::OnKbdAnswer),
        ..FakeAuth::default()
    });
    match go(
        fake_params(&server),
        vec![ssh::AuthMethod::KeyboardInteractive],
        Arc::new(CountingPrompter::answering_kbd(&["42"])),
    ) {
        Err(ssh::SshError::Connect(r)) => assert!(r.contains("lost during login"), "{r}"),
        other => panic!("expected Connect, got {other:?}"),
    }
}

/// A server whose refusal names no method russh knows: a refusal naming
/// what was tried, not a lost connection.
#[test]
fn a_server_offering_no_known_method_is_a_refusal() {
    let server = FakeServer::start(FakeAuth::default());
    match go(
        fake_params(&server),
        vec![ssh::AuthMethod::Password(ssh::Zeroizing::new("x".into()))],
        Arc::new(CountingPrompter::default()),
    ) {
        Err(ssh::SshError::AuthFailed(r)) => {
            assert!(r.contains("accepts none of the methods tried"), "{r}");
            assert!(r.contains("password x1"), "{r}");
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

/// A password asked before anything else is refused: the server's methods
/// are learned first (`none`), and a server without passwords is not asked
/// about.
#[test]
fn an_asked_password_first_learns_the_servers_methods() {
    let server = FakeServer::start(FakeAuth {
        kbd_rounds: vec![vec![("Code: ".into(), true, "42".into())]],
        ..FakeAuth::default()
    });
    let prompter = Arc::new(CountingPrompter::answering_password("x"));
    match go(
        fake_params(&server),
        vec![ssh::AuthMethod::AskPassword],
        Arc::clone(&prompter),
    ) {
        Err(ssh::SshError::AuthFailed(r)) => {
            assert!(r.contains("it offers: keyboard-interactive"), "{r}")
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
    assert_eq!(prompter.password_asked(), 0);
}
