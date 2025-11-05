# Ops directory

This folder centralises operational files used by the AI assistant:

- `ai-directives.txt` – bootstrap instructions for each chat session.
- `ai-large-message.txt` – scratchpad for oversized user prompts.
- `ai-tasks.txt` – resilient task list for multi-step work.
- `session-log.txt` – running log of active sessions and primers.
- `mutation-results.xml` – latest mutation-testing summary.

Keeping these files together keeps the repository root tidy while leaving the
existing workflow unchanged.
