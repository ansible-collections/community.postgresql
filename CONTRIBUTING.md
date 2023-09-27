# Contributing

Refer to the [Ansible Contributing guidelines](https://docs.ansible.com/ansible/devel/community/index.html) to learn how to contribute to this collection.

Refer to the [review checklist](https://docs.ansible.com/ansible/devel/community/collection_contributors/collection_reviewing.html) when triaging issues or reviewing PRs.

## Checking your code locally

### By hand

You can run flake8 with tox to verify the quality of your code. For that you
can simply call tox with that command:
``` console
$ tox -e lint
```

If you tox is missing on your environment you can probably install it through
your package manager (Eg: `sudo apt install tox`) or with pip (within a
virtualenv):

``` console
$ python3 -m venv .venv
$ source .venv
$ pip install tox
```

### Automatically for each commit

This repo contains some pre-commit configuration to automatically check your
code foreach commit. To use that configuration you should "install" it by
running:

``` console
$ pre-commit install
```

Then autoflake, flake8, isort and codespell must run when you add some commits.
You can also force them to run with this command:

``` console
$ pre-commit run --all-file
```

If pre-commit is missing on your system, you can install it (on Debian based
system) with `apt`:

``` console
$ sudo apt install pre-commit
```
