# Agent instructions for qsh

Before starting work, read `AGENTS_LOCAL.md` in this directory if it exists.
It contains additional instructions for this checkout. Keep it untracked and
do not copy its contents into committed files. If it is absent, continue with
these shared rules. Direct user instructions take priority.

## Language and authorship

All repository content must be in English, including documentation, plans,
source code, comments, tests, identifiers, agent instructions, commit messages,
and default user-facing text. Explicit localization resources for other
languages are the exception. Reply in the language the user is using unless
they explicitly request another language.
All public GitHub content, including issue and pull request titles, descriptions,
and comments, must be written in English.
Do not add model coauthorship trailers, assistant signatures, or session links.
Keep repository-language requirements in `AGENTS.md`; other documents should
not repeat them. `CLAUDE.md` refers to this file as the source of rules.
Public documentation describes qsh and qshd without promoting or describing a
separate client application. Preserve author provenance/risk warnings and
contribution/donation information when editing documentation. Public donation
addresses intentionally supplied by the owner are not private credentials.

## Before every GitHub push

Review the exact outgoing files and commit range for secrets and private data.
Use a local secret scanner with redacted output, then manually inspect fixtures,
configuration, logs, generated files, archives, personal paths, addresses,
author/committer identities, and commit messages. Before first publication or
making the repository public, scan every branch/tag intended for publication and its history.
Scan release artifacts separately before uploading them.

Follow [the privacy-check procedure](docs/private-data-check.md). Resolve every
finding; do not suppress entire test directories or treat a nonzero scan as
success. Keep raw reports outside the repository. Never send candidate secrets
to external validation services or print their values. Test keys must have
reviewed provenance and must never grant access to a real account or service.

Stop publication for unexplained findings. Real credentials require revocation
or rotation; deleting a file does not remove its historical copies. Do not
rewrite shared history or change repository visibility without explicit user
authorization. Running a scan does not authorize a push or release.

## Preserve the working environment

Stage only explicit task paths. Preserve unrelated work and user files.
Do not modify personal SSH keys, known-host files, agent state, qsh configuration,
or a user's running daemon. Run the `qsh` binary only inside a PTY test harness.
Tests that write state use temporary HOME/XDG directories and `HISTFILE=/dev/null`.
Report checks honestly; a successful formatting check must have empty output.

## Skill and agent artifacts

Keep skill and agent working artifacts local unless the user explicitly asks
for their inclusion in version control. This includes generated plans, session
notes, progress journals, review transcripts, intermediate reports, knowledge
graphs, caches, and temporary exports, regardless of which tool creates them.
Use ignored directories such as `.agent-work/`, `.superpowers/`,
`docs/superpowers/`, `.gstack/`, or `graphify-out/`; add a narrow ignore rule
before using another output directory. Do not force-add ignored artifacts or
follow a skill's default commit/publish step without that explicit request.

This does not exclude requested product changes or maintained project
documentation such as README, architecture, protocol, and contributor guides.
Inspect the staged paths before committing. Ignore rules do not untrack existing
files: preserve already tracked documents unless their removal or migration is
explicitly requested.
