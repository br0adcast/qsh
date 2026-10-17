//! Quoting for the one shell every command goes through.

/// `s` as one POSIX shell word.
pub(crate) fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Runs `script` under `sh`, whatever the account's login shell is: sshd
/// hands a command to the login shell, and fish or csh would read a POSIX
/// script differently.
pub(crate) fn posix(script: &str) -> String {
    format!("sh -c {}", quote(script))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_with_a_space_and_a_quote_is_one_word() {
        assert_eq!(quote("/home/a b/it's"), r"'/home/a b/it'\''s'");
    }

    #[test]
    fn every_command_goes_through_sh() {
        assert_eq!(posix("echo 'x'"), r"sh -c 'echo '\''x'\'''");
    }
}
