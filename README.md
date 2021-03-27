# PostgreSQL collection for Ansible
[![Build Status](
https://dev.azure.com/ansible/community.postgres/_apis/build/status/CI?branchName=main)](https://dev.azure.com/ansible/community.postgres/_build?definitionId=28)
[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.postgresql)](https://codecov.io/gh/ansible-collections/community.postgresql)

## Contributing to this collection

How to get started quickly, see the [CONTRIBUTING.md](CONTRIBUTING.md).

We use the following guidelines:

* [CONTRIBUTING.md](CONTRIBUTING.md)
* [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html)
* [Ansible Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/index.html)
* [Ansible Collection Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections)

We, [the PostgreSQL working group](https://github.com/ansible-collections/community.postgresql/wiki/PostgreSQL-Working-Group), use [the community pinboard](https://github.com/ansible-collections/community.postgresql/issues/30) for general announcements and discussions.

## External requirements

The PostgreSQL modules rely on the [Psycopg2](https://www.psycopg.org/docs/) PostgreSQL database adapter.

## Tested with Ansible

- 2.9
- 2.10
- devel

## Included content

- **Info modules**:
  - [postgresql_info](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_info_module.html)
  - [postgresql_ping](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_ping_module.html)
  - [postgresql_user_obj_stat_info](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_user_obj_stat_info_module.html)

- **Basic modules**:
  - [postgresql_db](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_db_module.html)
  - [postgresql_ext](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_ext_module.html)
  - [postgresql_lang](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_lang_module.html)
  - [postgresql_pg_hba](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_pg_hba_module.html)
  - [postgresql_privs](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_privs_module.html)
  - [postgresql_set](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_set_module.html)
  - [postgresql_schema](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_schema_module.html)
  - [postgresql_tablespace](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_tablespace_module.html)
  - [postgresql_query](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_query_module.html)
  - [postgresql_user](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_user_module.html)

- **Other modules**:
  - [postgresql_copy](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_copy_module.html)
  - [postgresql_idx](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_idx_module.html)
  - [postgresql_membership](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_membership_module.html)
  - [postgresql_owner](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_owner_module.html)
  - [postgresql_publication](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_publication_module.html)
  - [postgresql_sequence](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_sequence_module.html)
  - [postgresql_slot](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_slot_module.html)
  - [postgresql_subscription](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_subscription_module.html)
  - [postgresql_table](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_table_module.html)

## Using this collection

### Installing the Collection from Ansible Galaxy

Before using the PostgreSQL collection, you need to install it with the Ansible Galaxy CLI:

```bash
ansible-galaxy collection install community.postgresql
```

You can include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: community.postgresql
```

You can also download the tarball from Ansible Galaxy and install the collection manually wherever you need.

See [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Release notes

See the [changelog](https://github.com/ansible-collections/community.postgresql/blob/main/CHANGELOG.rst).

## Roadmap

See the [release plan](https://github.com/ansible-collections/community.postgresql/issues/13).

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
