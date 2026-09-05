# AGENTS.md

Repo-wide guidance for agents working in this repository. `CLAUDE.md` is a
symlink to this file so Claude Code loads the same guidance.

## Repository layout

The superproject pins its submodules under `dep/` via gitlinks. In every
submodule, `origin` is the kkdwvd fork.

- `dep/kkd` — personal tooling monorepo (provides `kdev`); branch `main`
  tracks `origin/main`.

`src/` is reserved for lachesis-native code and `build/` for generated
outputs; `build/` is ignored by git.

## Submodules

- The gitlinks pin exact submodule commits. `git submodule update --init`
  restores those commits; do not add `--remote` unless intentionally updating
  the pinned versions.
- Always keep complete history: no `--depth`, `--shallow-submodules`, or
  `shallow = true` for any submodule.
- Fresh clones leave submodules on detached HEADs. Attach the working branches
  at the pinned commits before using the sync or rebase targets:

  ```sh
  git -C dep/kkd checkout -B main HEAD
  git -C dep/kkd branch --set-upstream-to=origin/main main
  ```

- These attachment commands are for fresh clones only. Do not rerun them over
  submodules that already contain local work.

## Builds

- The root `Makefile` currently only drives submodule maintenance. Run
  `make help` for the target list and overridable variables instead of relying
  on this file to enumerate them.
- `kdev` comes from the pinned `dep/kkd` submodule, not from a system install.

## Sync and rebase

- `make sync` (or per-repo `kkd-sync`): pull and rebase each attached branch
  onto its fork tracking branch. Sync never pushes.
- `make rebase` (or per-repo `-rebase` variants): advance the patch stacks —
  fetch the true upstream base, rebase the attached branch onto it, then
  force-push (`--force-with-lease`) the branch back to the fork. Every step is
  a no-op when already current, so re-running is always safe. `dep/kkd` has no
  separate upstream, so its rebase base is `origin/main`.
- Both reject detached HEADs and tracked or staged changes; untracked files
  are left alone.
- If a rebase conflicts, `make rebase` continues with the remaining repos and
  lists the failures. Resolve the conflicts, `git rebase --continue`, then
  re-run `make rebase` to finish and push.
- Syncing and rebasing are explicit maintenance operations. Never make them
  prerequisites of `all` or any other build target.
- Afterwards, review the updated submodule commits and stage the resulting
  superproject gitlink bumps intentionally.

## Git conventions

- Use `--no-gpg-sign` when creating or amending commits to avoid GPG signing
  issues.
- Agent-authored commit messages start with the authoring agent in
  parentheses, then read like a short sentence fragment, for example:
  `(codex) Initialize the repository` or `(claude) Harden the sync guards`.
- Wrap every commit message line, subject and body alike, at 80 columns.
  Use real newlines; never emit literal `\n` escapes in commit messages.
