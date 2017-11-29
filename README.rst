================================
AWS Process Credential Providers
================================

.. image:: https://travis-ci.org/awslabs/awsprocesscreds.svg?branch=master
   :target: https://travis-ci.org/awslabs/awsprocesscreds

A collection of process-based credential providers to be used with the AWS CLI
and related tools.


Installation
------------

The easiest way to install is to use pip::

    pip install awsprocesscreds

Requirements
~~~~~~~~~~~~

This package requires a version of python to be installed. Currently supported
python versions are:

* 2.7.9+
* 3.3.x
* 3.4.x
* 3.5.x
* 3.6.x


SAML Forms-Based Authentication
-------------------------------

If you have a SAML identity provider, you can use `awsprocesscreds-saml` to
configure programmatic access to your AWS resources. It has four required
arguments:

* ``-e / --endpoint`` - Your SAML idp endpoint.
* ``-u / --username`` - Your SAML username.
* ``-p / --provider`` - The name of your SAML provider. Currently okta and
  adfs are supported.
* ``-a / --role-arn``- The role arn you wish to assume. Your SAML provider
  must be configured to give you access to this arn.


This will cache your credentials by default, which will allow you to run
multiple commands without having to enter your password each time. You can
disable the cache by specifying ``--no-cache``.

Additionally, you can show logs by specifying ``-v`` or ``--verbose``.

To configure this provider, you need create a profile using the
``credential_process`` config variable. See the `AWS CLI Config docs`_
for more details on this config option.


Example okta configuration::

    [profile okta]
    region = us-west-2
    credential_process = awsprocesscreds-saml -e https://example.okta.com/home/amazon_aws/blob/123 -u 'monty@example.com' -p okta -a arn:aws:iam::123456789012:role/okta-dev

Example adfs configuration::

    [profile adfs]
    region = us-west-2
    credential_process = awsprocesscreds-saml -e 'https://corp.example.com/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices' -u Monty -p adfs -a arn:aws:iam::123456789012:role/ADFS-Dev

.. _AWS CLI Config docs: http://docs.aws.amazon.com/cli/latest/topic/config-vars.html#cli-aws-help-config-vars
