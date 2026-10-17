# Check private data before publishing

Run this check before every GitHub push and before uploading release artifacts.
A secret scanner recognizes credentials; manual review must also cover personal
paths, identifying metadata, real hostnames, and other private information.

## Scan only the refs intended for publication

Identify the exact branches and tags intended for publication and scan their
reachable history. Push explicit refs; avoid `git push --all` or `--mirror`,
which can publish unrelated local refs. Keep private working files out of the
index and inspect the staged paths before committing.

[Gitleaks](https://github.com/gitleaks/gitleaks) scans Git history and files
locally. Obtain the scanner from its official distribution and verify the
published checksum. No source or candidate credential needs to be sent to a
third party for validation.

From the repository root, with Gitleaks installed:

```bash
audit_dir="$(mktemp -d)"
chmod 700 "$audit_dir"

# Full history of the branch intended for publication, including merge diffs.
gitleaks git --log-opts='main --full-history -m' \
  --redact=100 --ignore-gitleaks-allow --max-archive-depth=2 \
  --report-format=json --report-path="$audit_dir/history.json" .

# Complete committed public snapshot, without local settings or build outputs.
mkdir "$audit_dir/source"
git archive main -o "$audit_dir/source.tar"
tar -xf "$audit_dir/source.tar" -C "$audit_dir/source"
gitleaks dir "$audit_dir/source" --redact=100 --ignore-gitleaks-allow \
  --max-archive-depth=2 --report-format=json \
  --report-path="$audit_dir/files.json"

# Inspect staged changes too; repeat the committed checks after committing.
gitleaks git --staged --redact=100 --ignore-gitleaks-allow .
```

Run and inspect each command separately. Exit 1 means findings, not success;
other errors also need investigation. The archive represents committed `main`,
not unstaged edits or untracked files. Inspect those before staging. For later
pushes, also review the exact outgoing range, such as `origin/main..HEAD`.

Do not exclude whole test directories, suppress private-key rules, or accept a
baseline merely because its findings are old. Public test suites generate fresh
private keys in temporary directories; no fixed SSH private key is needed in
version control. Public donation addresses deliberately published by the owner
are not private keys; preserve them exactly and review their intended publication
separately from credentials. Do not remove author warnings or support information
as part of a privacy cleanup without an explicit request.

## Manual review

Review files, outgoing history, and metadata for:

- Passwords, API tokens, signing keys, SSH private keys, cookies, recovery codes,
  credentials in URLs, and secrets inside archives.
- Real connection profiles, knock sequences, internal hostnames, IP addresses,
  account names, absolute personal paths, logs, screenshots, or exported sessions.
- Author/committer names and emails, commit messages, README contacts, package
  maintainer fields, and financial addresses. Use an approved public identity
  and a GitHub noreply email for public commits.
- Included files, debug paths, package metadata, and build logs in release
  artifacts. A source-only scan does not audit previously uploaded binaries.

Keep raw reports outside version control and redact excerpts before sharing.
If a real credential is found, arrange revocation/rotation first; deleting the
current file leaves its historical copies. Rewriting shared history and changing
repository visibility require the owner's explicit authorization.

## When replacing private history

After an explicitly authorized history cleanup, publish only reviewed refs.
Check whether remote branches or tags still expose the removed data.
Do not assume a force-push erases old releases, Actions logs/artifacts, pull
request refs, forks, or cached commit views. Review those separately before
making the repository public; follow
[GitHub's sensitive-data removal guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
for server-side retention that cannot be addressed through ordinary Git refs.

After publication, [GitHub secret scanning](https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning)
is an additional layer, not a replacement for this pre-push check.
