=============================================
Community PostgreSQL Collection Release Notes
=============================================

.. contents:: Topics


v1.5.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 1.4.0.

Minor Changes
-------------

- postgresql_db - Add the ``force`` boolean option to drop active connections first and then remove the database (https://github.com/ansible-collections/community.postgresql/issues/109).
- postgresql_info - Add the ``raw`` return value for extension version (https://github.com/ansible-collections/community.postgresql/pull/138).
- postgresql_pg_hba - Add the parameters ``keep_comments_at_rules`` and ``comment`` (https://github.com/ansible-collections/community.postgresql/issues/134).

Bugfixes
--------

- postgresql_ext - Fix extension version handling when it has 0 value (https://github.com/ansible-collections/community.postgresql/issues/136).
- postgresql_info - Fix extension version handling when it has 0 value (https://github.com/ansible-collections/community.postgresql/issues/137).
- postgresql_set - Fix wrong numerical value conversion (https://github.com/ansible-collections/community.postgresql/issues/110).
- postgresql_slot - Correct the server_version check for PG 9.6 (https://github.com/ansible-collections/community.postgresql/issue/120)

v1.4.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 1.3.0.

Minor Changes
-------------

- postgresql_db - add support for the ``directory`` format when the ``state`` option is ``dump`` or ``restore`` (https://github.com/ansible-collections/community.postgresql/pull/108).
- postgresql_db - add the ``rename`` value to the ``state`` option (https://github.com/ansible-collections/community.postgresql/pull/107).

v1.3.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 1.2.0.

Major Changes
-------------

- postgresql_query - the default value of the ``as_single_query`` option will be changed to ``yes`` in community.postgresql 2.0.0 (https://github.com/ansible-collections/community.postgresql/issues/85).

Bugfixes
--------

- postgresql_privs - fix ``fail_on_role`` check (https://github.com/ansible-collections/community.postgresql/pull/82).

v1.2.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 1.1.1.

Minor Changes
-------------

- postgresql_info - add the ``patch``, ``full``, and ``raw`` values of the ``version`` return value (https://github.com/ansible-collections/community.postgresql/pull/68).
- postgresql_ping - add the ``patch``, ``full``, and ``raw`` values of the ``server_version`` return value (https://github.com/ansible-collections/community.postgresql/pull/70).

v1.1.1
======

Release Summary
---------------

This is the patch release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 1.1.0.

Bugfixes
--------

- postgresql_query - add a warning to set ``as_single_query`` option explicitly (https://github.com/ansible-collections/community.postgresql/pull/54).
- postgresql_query - fix datetime.timedelta type handling (https://github.com/ansible-collections/community.postgresql/issues/47).
- postgresql_query - fix decimal handling (https://github.com/ansible-collections/community.postgresql/issues/45).
- postgresql_set - fails in check_mode on non-numeric values containing `B` (https://github.com/ansible-collections/community.postgresql/issues/48).

v1.1.0
======

Release Summary
---------------

This is the minor release of the ``community.postgresql`` collection.
This changelog contains all changes to the modules in this collection that
have been added after the release of ``community.postgresql`` 1.0.0.

Minor Changes
-------------

- postgresql_query - add ``as_single_query`` option to execute a script content as a single query to avoid semicolon related errors (https://github.com/ansible-collections/community.postgresql/pull/37).

Bugfixes
--------

- postgresql_info - fix crash caused by wrong PgSQL version parsing (https://github.com/ansible-collections/community.postgresql/issues/40).
- postgresql_ping - fix crash caused by wrong PgSQL version parsing (https://github.com/ansible-collections/community.postgresql/issues/40).
- postgresql_set - return a message instead of traceback when a passed parameter has not been found (https://github.com/ansible-collections/community.postgresql/issues/41).

v1.0.0
======

Release Summary
---------------

This is the first proper release of the ``community.postgresql`` collection which is needed to include the collection in Ansible.
This changelog does not contain any changes because there are no changes made since release 0.1.0.


v0.1.0
======

Release Summary
---------------

The ``community.postgresql`` continues the work on the Ansible PostgreSQL
modules from their state in ``community.general`` 1.2.0.
The changes listed here are thus relative to the modules ``community.general.postgresql_*``.


Minor Changes
-------------

- postgresql_info - add ``in_recovery`` return value to show if a service in recovery mode or not (https://github.com/ansible-collections/community.general/issues/1068).
- postgresql_privs - add ``procedure`` type support (https://github.com/ansible-collections/community.general/issues/1002).
- postgresql_query - add ``query_list`` and ``query_all_results`` return values (https://github.com/ansible-collections/community.general/issues/838).

Bugfixes
--------

- postgresql_ext - fix the module crashes when available ext versions cannot be compared with current version (https://github.com/ansible-collections/community.general/issues/1095).
- postgresql_ext - fix version selection when ``version=latest`` (https://github.com/ansible-collections/community.general/pull/1078).
- postgresql_privs - fix module fails when ``type`` group and passing ``objs`` value containing hyphens (https://github.com/ansible-collections/community.general/issues/1058).
