---
name: run-tests
description: Runs and writes tests (sanity, unit, integration) for the community.postgresql Ansible collection using ansible-test. Use when asked to run, check, or write tests for a module or utility. Do not use for PR reviews or questions unrelated to testing.
---

# Skill: run-tests

## Purpose

Run and write tests for the `community.postgresql` Ansible collection. Covers sanity, unit, and integration tests using `ansible-test`.

## When to Invoke

TRIGGER when:
- A user asks to run tests, check tests, or verify changes with tests
- A user asks how to test a module or utility
- A user asks to write tests for new or modified code

DO NOT TRIGGER when:
- Reviewing a PR for overall quality (use `.agents/skills/pr-review/SKILL.md` instead)
- The question is about module logic unrelated to testing

## Test Infrastructure

All tests run inside Docker/Podman via `ansible-test --docker`. No local package installation is needed. The collection must be installed at `ansible_collections/community/postgresql/` (relative to a directory on `ANSIBLE_COLLECTIONS_PATHS`) for imports to resolve correctly.

---

## Test Commands

### Sanity

Checks style, documentation, and imports for a changed file:

```bash
ansible-test sanity plugins/modules/postgresql_db.py --docker -vvv
```

### Unit

Runs unit tests for changed files:

```bash
ansible-test units tests/unit/plugins/modules/test_postgresql_query.py --docker -vvv
ansible-test units tests/unit/plugins/module_utils/test_pg_membership.py --docker -vvv
```

Unit tests live under `tests/unit/plugins/` and use the **PyTest** framework. Every new function or class method MUST have a corresponding unit test.

### Integration

Runs integration tests against a live PostgreSQL instance (started by Docker):

```bash
ansible-test integration postgresql_db --docker default -vvv
ansible-test integration postgresql_user --docker default -vvv
```

Integration tests live under `tests/integration/targets/<module_name>/`. Each target declares `setup_postgresql_db` as a dependency in `tests/integration/targets/<name>/meta/main.yml` — this target installs the PostgreSQL server.

---

## When Tests Are Required

| Change type | Sanity | Unit | Integration |
|---|---|---|---|
| New module | yes | yes | yes |
| New parameter | yes | if logic changed | yes |
| Bug fix | yes | yes | yes |
| Refactoring | yes | yes | no |
| Documentation only | yes | no | no |

---

## Integration Test Pattern

Every integration test target must follow this sequence:

1. Call the module under test → `register: result`
2. Assert on `result` using `ansible.builtin.assert`
3. Verify the resulting database state by querying via `community.postgresql.postgresql_query` → `register: result` → `ansible.builtin.assert`
4. This must be done in `check_mode: true` as well

```yaml
- name: Create database in check mode
  check_mode: true
  community.postgresql.postgresql_db:
    name: testdb
    state: present
  register: result

- name: Assert changed
  ansible.builtin.assert:
    that:
      - result is changed

- name: Verify DB does not exist in PostgreSQL
  community.postgresql.postgresql_query:
    query: "SELECT datname FROM pg_database WHERE datname = 'testdb'"
  register: result

- name: Assert DB is not present
  ansible.builtin.assert:
    that:
      - result.query_result | length == 0

- name: Create database in real mode
  community.postgresql.postgresql_db:
    name: testdb
    state: present
  register: result

- name: Assert changed
  ansible.builtin.assert:
    that:
      - result is changed

- name: Verify DB exists in PostgreSQL
  community.postgresql.postgresql_query:
    query: "SELECT datname FROM pg_database WHERE datname = 'testdb'"
  register: result

- name: Assert DB is present
  ansible.builtin.assert:
    that:
      - result.query_result | length == 1
```

Tests must also cover:
- **Idempotency**: run the same task a second time and assert `result is not changed`.
- **`state: absent`**: where applicable, remove the resource and assert it is gone.
