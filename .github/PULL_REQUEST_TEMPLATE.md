## What and why

<!-- What does this change do, and what problem does it solve? Link the issue: Fixes #123 -->

## How I tested it

<!-- Commands you ran and what you saw. A bug fix should include a test that failed before the fix. -->

## Checklist

- [ ] `cd backend && python -m pytest tests -q` passes
- [ ] `cd frontend && npm run typecheck && npm run build` passes (if the UI changed)
- [ ] I added or updated tests, including the **refusal** path for scope, Governor, replay, impact, verifier or sandbox changes
- [ ] No attack text, credential or personal data was added to code; test content is harmless marker text in the library
- [ ] Every request that can reach a target still goes through the signed-scope gate and the Governor
- [ ] Docs are updated (README, `docs/ARCHITECTURE.md`) if behavior changed
- [ ] UI changes keep the current look; empty states and error messages tell the person what to do next

## Screenshots (UI changes)

<!-- Before and after. -->
