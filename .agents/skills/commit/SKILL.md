---
name: commit
description: "This skill should be used when the user asks to 'commit', 'create a commit', or 'git commit'. It creates conventional commits with FQCN scopes for Ansible collection content (roles, modules, plugins)."
---

You are executing the `commit` skill. Follow these steps precisely.

## Step 1: Determine Assisted-by

Identify the model you are currently running as from your system context.
Format it as `Assisted-by: <Model> <Version>` — e.g. `Claude Sonnet 4.6`, `GPT 5.3 Codex`.
This trailer will be appended to every commit created in this session.

## Step 2: Infer commit type

Follow the [Conventional Commits 1.0.0 standard](https://www.conventionalcommits.org/en/v1.0.0).

Infer a commit type based on either a changelog fragment for the changes if present or on the nature of the changes made.

If the type is ambiguous, use `AskUserQuestion` to ask:
"What type of change is this for `<component>`? (feat/fix/docs/chore/refactor/ci/deprecate/remove/breaking)"

## Step 3: Draft commit message

Follow conventional commits format:
- **Component-specific**: `<type>(<component>): <imperative short description>`
- **Project-level (no scope)**: `<type>: <imperative short description>`

Rules:
- Subject line ≤ 72 characters
- Lowercase after the colon and space
- No trailing period
- Use imperative mood (e.g. "add", "fix", "remove" — not "added", "fixes")
- For breaking changes, append a blank line and `BREAKING CHANGE: <explanation>` in the body
- Always append a blank line followed by `Assisted-by: <AI tool/mode and its version>` (from Step 1) at the end of every message

Examples:
```
feat: add support for custom agent port to postgresql_info module

Assisted-by: Claude Sonnet 4.6
```

```
feat!: drop support for ansible-core <= 2.16

BREAKING CHANGE: ansible-core 2.16 and earlier are no longer supported.

Assisted-by: Claude Sonnet 4.6
```

## Step 4: Confirm with user

Use `AskUserQuestion` to present the proposed commit message and ask for approval:

"Proposed commit ```\n<message>\n```\n\nApprove, or provide an edited message?"

If the user provides an edited message, use their version exactly.

## Step 5: Commit

Run git add <relevant files> and commit.
