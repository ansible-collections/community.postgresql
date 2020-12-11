# PostgreSQL collection for Ansible
[![Build Status](
https://dev.azure.com/ansible/community.postgres/_apis/build/status/CI?branchName=main)](https://dev.azure.com/ansible/community.postgres/_build?definitionId=28)
[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.postgresql)](https://codecov.io/gh/ansible-collections/community.postgresql)

## External requirements

The PostgreSQL modules rely on the [Psycopg2](https://www.psycopg.org/docs/) PostgreSQL database adapter.

## Tested with Ansible

- 2.9
- 2.10
- devel

## Included content

- **Info modules**:
  - [postgresql_info](https://docs.ansible.com/ansible/latest/modules/postgresql_info_module.html)
  - [postgresql_ping](https://docs.ansible.com/ansible/latest/modules/postgresql_ping_module.html)
  - [postgresql_user_obj_stat_info](https://docs.ansible.com/ansible/latest/modules/postgresql_user_obj_stat_info_module.html)

- **Basic modules**:
  - [postgresql_db](https://docs.ansible.com/ansible/latest/modules/postgresql_db_module.html)
  - [postgresql_ext](https://docs.ansible.com/ansible/latest/modules/postgresql_ext_module.html)
  - [postgresql_lang](https://docs.ansible.com/ansible/latest/modules/postgresql_lang_module.html)
  - [postgresql_pg_hba](https://docs.ansible.com/ansible/latest/modules/postgresql_hba_module.html)
  - [postgresql_privs](https://docs.ansible.com/ansible/latest/modules/postgresql_privs_module.html)
  - [postgresql_set](https://docs.ansible.com/ansible/latest/modules/postgresql_set_module.html)
  - [postgresql_schema](https://docs.ansible.com/ansible/latest/modules/postgresql_schema_module.html)
  - [postgresql_tablespace](https://docs.ansible.com/ansible/latest/modules/postgresql_tablespace_module.html)
  - [postgresql_query](https://docs.ansible.com/ansible/latest/modules/postgresql_query_module.html)
  - [postgresql_user](https://docs.ansible.com/ansible/latest/modules/postgresql_user_module.html)

- **Other modules**:
  - [postgresql_copy](https://docs.ansible.com/ansible/latest/modules/postgresql_copy_module.html)
  - [postgresql_idx](https://docs.ansible.com/ansible/latest/modules/postgresql_idx_module.html)
  - [postgresql_membership](https://docs.ansible.com/ansible/latest/modules/postgresql_membership_module.html)
  - [postgresql_owner](https://docs.ansible.com/ansible/latest/modules/postgresql_owner_module.html)
  - [postgresql_publication](https://docs.ansible.com/ansible/latest/modules/postgresql_publication_module.html)
  - [postgresql_sequence](https://docs.ansible.com/ansible/latest/modules/postgresql_sequence_module.html)
  - [postgresql_slot](https://docs.ansible.com/ansible/latest/modules/postgresql_slot_module.html)
  - [postgresql_subscription](https://docs.ansible.com/ansible/latest/modules/postgresql_subscription_module.html)
  - [postgresql_table](https://docs.ansible.com/ansible/latest/modules/postgresql_table_module.html)

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

## Contributing to this collection

<!--Describe how the community can contribute to your collection. At a minimum, include how and where users can create issues to report problems or request features for this collection.  List contribution requirements, including preferred workflows and necessary testing, so you can benefit from community PRs. If you are following general Ansible contributor guidelines, you can link to - [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html). -->

We're following the general Ansible contributor guidelines; see [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html).

If you want to clone this repositority (or a fork of it) to improve it, you can proceed as follows:
1. Create a directory `ansible_collections/community`;
2. In there, checkout this repository (or a fork) as `postgresql`;
3. Add the directory containing `ansible_collections` to your [ANSIBLE_COLLECTIONS_PATH](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths).

See [Ansible's dev guide](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections) for more information.

There is also [the community pinboard](https://github.com/ansible/community/issues/435) used by [the PostgreSQL working group](https://github.com/ansible/community/wiki/PostgreSQL) for announcements and discussing general questions.

## Release notes

See the [changelog](https://github.com/ansible-collections/community.postgresql/blob/main/CHANGELOG.rst).

## Roadmap

See the [release plan](https://github.com/ansible-collections/community.postgresql/issues/13).
See blah blah

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

<!-- Include the appropriate license information here and a pointer to the full licensing details. If the collection contains modules migrated from the ansible/ansible repo, you must use the same license that existed in the ansible/ansible repo. See the GNU license example below. -->

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
