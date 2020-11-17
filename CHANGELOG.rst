=============================================
Community PostgreSQL Collection Release Notes
=============================================

.. contents:: Topics


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
