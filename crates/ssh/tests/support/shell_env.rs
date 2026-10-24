//! Private startup state for integration fixtures, never the product's shell policy.
//!
//! The invoking account still selects sshd's command interpreter. This controls
//! its user startup files and the shell qshd subsequently starts; system startup
//! configuration remains a prerequisite of the disposable acceptance environment.

use std::path::Path;

pub fn prepare(home: &Path, shell: &Path) -> Vec<(String, String)> {
    for directory in [".cache", ".config"] {
        std::fs::create_dir_all(home.join(directory)).expect("private shell directory");
    }
    // Presence prevents zsh-newuser-install from consuming the first command.
    // GLOBAL_RCS disables subsequent system rc files after /etc/zshenv, which
    // necessarily runs first and cannot be isolated by a per-child environment.
    for (name, contents) in [
        (".zshenv", "unsetopt GLOBAL_RCS\n"),
        (".zshrc", ""),
        (".bashrc", ""),
        (".bash_profile", ""),
        (".profile", ""),
    ] {
        std::fs::write(home.join(name), contents).expect("private shell startup file");
    }
    let home = home.to_str().expect("UTF-8 private home");
    vec![
        ("HOME".into(), home.into()),
        ("XDG_CACHE_HOME".into(), format!("{home}/.cache")),
        ("XDG_CONFIG_HOME".into(), format!("{home}/.config")),
        ("ZDOTDIR".into(), home.into()),
        ("SHELL".into(), shell.to_str().expect("UTF-8 shell").into()),
        ("BASH_ENV".into(), "/dev/null".into()),
        ("ENV".into(), "/dev/null".into()),
        ("HISTFILE".into(), "/dev/null".into()),
    ]
}

pub fn quote(value: &Path) -> String {
    format!(
        "'{}'",
        value.to_str().expect("UTF-8 path").replace('\'', "'\\''")
    )
}
