# Contributing

Refer to the [Ansible Contributing guidelines](https://docs.ansible.com/ansible/devel/community/index.html) to learn how to contribute to this collection.

Refer to the [review checklist](https://docs.ansible.com/ansible/devel/community/collection_contributors/collection_reviewing.html) when triaging issues or reviewing PRs.

## Checking your code locally

You can run flake8 with tox to verify the quality of your code. For that you can simply call tox with that command:
``` console
$ tox -e lint
```

If you tox is missing on your environment you can probably install it through your package manager (Eg: `sudo apt
install tox`) or with pip (within a virtualenv):

``` console
$ python3 -m venv .venv
$ source .venv
$ pip intall tox
```
