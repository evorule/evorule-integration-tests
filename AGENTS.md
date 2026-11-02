# AGENTS.md - agent session entry notes (repo: evorule-integration-tests)

> Any agent session working in this repo reads this file first.

1. **Disclosure rules**: internal registry ids (letter-prefixed numbers), private
   paths, real credentials, internal operations details, and session traces must
   never appear in any file or commit message. The CI ratchet scan is in force:
   the existing baseline is frozen and new violations turn red.
2. **Commit messages** use neutral conventional wording (feat/fix/docs/chore +
   summary) with no internal ids; the local hook intercepts violations at
   commit time.
3. **Repo entry**: README.md; follow the in-repo CI gates and contribution
   rules when making changes.
