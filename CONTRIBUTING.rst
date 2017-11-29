============
Contributing
============

We work hard to provide high-quality and useful process providers, and we
greatly value feedback and contributions from our community. Whether it's a new
feature, correction, or additional documentation, we welcome your pull
requests. Please submit any issues or pull requests through GitHub.

This document contains guidelines for contributing code and filing issues.


Contributing Code
-----------------

The list below serves as guidelines to use when submitting pull requests. These
are the same set of guidelines that the core contributers use when submitting
changes, and we ask the same of all community contributions as well.

* awsprocesscreds is released under the
  `Apache license <https://aws.amazon.com/apache2.0/>`__. Any code you submit
  will be released under that license.
* We maintain a high percentage of code coverage in our tests. As a general
  rule, code changes should not lower the overall code coverage percentage for
  the project. To help with this, we use codecov, which will comment on changes
  in code coverage for every pull request. In practice, this means that every
  bug fix and feature addition should include unit tests, and optionally
  functional and integration tests.
* All PRs must run cleanly through ``make prcheck``. This is described in more
  detail in the sections below.
* All new features must include documentation before they can be merged.


Feature Development
-------------------

Any significant feauture development for awsprocesscreds should have a
corresponding github issue for discussion. This gives several benefits:

* Helps avoid wasted work by discussing the proposed API changes before
  significant dev work is started.
* Gives a single place to capture discussion about the rationale for
  a feature.

If you would like to implement a significant feature for awsprocesscreds,
please file an issue to start the design discussion.


Development Environment Setup
-----------------------------

First, create a virtual environment for awsprocesscreds::

    $ virtualenv venv-awsprocesscreds
    $ source venv-awsprocesscreds/bin/activate

Keep in mind the supported python versions. We currently support 2.7.9+ and
3.3.0-3.6.x.

Next you'll need to install awsprocesscreds. The easiest way to configure this
is to use::

    $ pip install -e .

Run that command in the root directory of the awsprocesscreds repo.

Next, you will need to install the development requirements. You can do this by
installing ``requirements-dev.txt`` like so::

    $ pip install -r requirements-dev.txt


Running Tests
-------------

awsprocesscreds uses `pytest <https://docs.pytest.org/en/latest/>`__ to run
tests. The tests are categorized into 3 categories:

* ``unit`` - Fast tests that don't make any IO calls (including file system
  access). Object dependencies are usually mocked out.
* ``functional`` - These tests will test multiple components together,
  typically through an interface that's close to what an end user would
  be using. For example, there are SAML cli functional tests that wil invoke
  the same function that the ``awsprocesscreds-saml`` entry point will.
* ``integration`` - These tests require an AWS account and will create real
  AWS resources.

During development, you'll generally run the unit tests, and less frequently
you'll run the functional tests (the functional tests take an order of
magnitude longer than the unit tests). To run the unit tests, you can run::

    $ py.test tests/unit/

To run the functional tests you can run::

    $ py.test tests/functional/

There's also a ``Makefile`` in the repo and you can run ``make test`` to run
both the unit and functional tests.


Code Analysis
-------------

awsprocesscreds uses several python linters to help ensure high code quality.
This also helps to cut down on the noise for pull request reviews because many
issues are caught locally during development.

To run all the linters, you can run ``make check``. This will run:

* `flake8 <http://flake8.pycqa.org/en/latest/>`__, a tool for checking pep8 as
  well as common lint checks.
* `pydocstyle <https://github.com/PyCQA/pydocstyle>`__, a docstring checker.
* `pylint <https://www.pylint.org/>`__, a much more exhaustive linter that can
  catch additional issues compared to ``flake8``.


Code Coverage
-------------

To generate code coverage reports, you can run ``make coverage``. This will run
all the functional and unit tests to guage the coverage percentage. Remember
pull requests should not decrease overall coverage.


PRCheck
-------

Before submitting a PR, ensure that ``make prcheck`` runs without any errors.
This command will run the linters, the typecheckers and the unit and functional
tests. ``make prcheck`` is also run as part of the travis CI build. Pull
requests must pass ``make prcheck`` before they can be merged.

