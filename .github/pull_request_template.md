<!-- markdownlint-disable MD041 -->
## What this changes

<!-- What the change does and why. Link the issue it resolves, for example "Closes #123". -->

## How it was verified

<!-- The commands you ran, plus anything you exercised manually against a cluster. -->

## Notes for reviewers

<!-- Optional. Anything that is not obvious from the diff: a behaviour change, a migration
     step for existing installs, a deliberate trade-off or a follow-up you left out. -->

## Checklist

- [ ] `make lint` and `make test` pass locally
- [ ] `make manifests generate` was rerun and the result committed, if anything under `api/` changed
- [ ] `README.md` and `docs/` match the new behaviour
- [ ] `RELEASE_NOTES.md` has an entry, if a user can observe this change
- [ ] Any new workflow action is pinned to a commit SHA
