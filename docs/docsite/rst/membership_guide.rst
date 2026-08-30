.. _ansible_collections.community.postgresql.docsite.membership_guide:

How postgresql_membership decides which grants to modify
========================================================

From PostgreSQL 16 on, a role membership is not one fact but one grant per
granting role, each carrying its own ``ADMIN``, ``INHERIT`` and ``SET``
options. The ``memberships`` option of
:ansplugin:`community.postgresql.postgresql_membership#module` therefore has
to decide, for every row, whose grant it manages before it can decide what to
change. This page shows that decision as one tree. Everything below assumes
PostgreSQL 16 or later; before 16 a pair has exactly one grant and no options,
so every branch collapses into the same behaviour.

Step 0 resolves, per row, whose grant it manages::

    granted_by_any (row, else task level when no granted_by) ?
    |-- true ---------> manages EVERY grant of its pairs          [G = any]
    |-- granted_by: X -> manages the grant recorded under X       [G = X]
    '-- neither ------> manages the grant under the derived role  [G = derived]
                        (bootstrap superuser if the connecting role is a
                         superuser, else CURRENT_ROLE)

Then the task builds one wanted grant per (row, target role, group) and reads
the server's grants of every pair once, before anything is emitted. All
decisions below compare against that snapshot, and roles not named in
``target_roles`` are never touched.

``state=present``, per wanted grant::

    G = any:  does ANY grant of the pair exist?
              |-- yes -> nothing
              '-- no --> GRANT group TO role            (server picks grantor)

    G = X or derived:  does the grant under G exist?
              |-- no --> GRANT ... [WITH <options>] GRANTED BY G       (1)(2)
              |-- yes, but a named option key differs from it
              |        -> same GRANT again, restating every named option
              '-- yes, options match or none named -> nothing
                        (a foreign grant never satisfies the request; one that
                         keeps a cleared option alive only draws a warning)

    (1) before the first statement, and only for grants that will be emitted:
        the connecting role must have the privileges of every named X, and
        G must hold ADMIN OPTION on the group (waived for the bootstrap
        superuser); the failure names the roles that do hold it
    (2) all wanted GRANTs are decided first, so one refused grant stops the
        task before anything runs

``state=absent``, per wanted grant::

    G = any:  one REVOKE ... GRANTED BY <grantor> per grant found, after
              checking the privileges over every one of those grantors

    G = X or derived:  does the grant under G exist?
              |-- yes -> REVOKE ... GRANTED BY G   (privileges of X checked)
              '-- no --> nothing
              plus a warning for every OTHER grant that keeps the membership
              alive, whether or not something was revoked

``state=exact`` is a prune pass followed by the ``state=present`` logic::

    per TARGET ROLE, every group it is a member of that no row names for it:
        task-level granted_by_any ?
        |-- true --> revoke EVERY grant of it (as G = any, privileges checked)
        '-- false -> revoke the grant under the DERIVED role only;
                     a foreign grant survives with a warning pointing at a
                     state=absent task with granted_by
    then every wanted grant is granted or reconciled exactly as in present.

Two properties hold throughout: ``changed`` is true exactly when at least one
``GRANT`` or ``REVOKE`` was emitted, and the whole task is one transaction, so
a failure at any branch leaves the server untouched.
