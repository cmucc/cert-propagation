# cert-propagation scripts

The Carnegie Mellon Computer Club's cert-propagation scripts facilitate
configuring a single host with an ACME client, e.g. EFF's `certbot`, and
then distributing the acquired certificates to one or more other hosts that
run services requiring them.

Currently there are two scripts:

* `cert_receive.py` — runs on hosts with services requiring certificates;
  validates and installs certificates and keys

* `certbot_send.sh` — runs as a `certbot` deploy hook; connects to remote
  hosts with `ssh` and provides certificate and key data using the protocol
  defined by `cert_receive.py`

## cert\_receive.py

Typically `cert_receive.py` will run as a forced command executed when the
`root` user connects to a service host via `ssh` using a designated private
key.  This is done with an `authorized_keys` entry, similar to the
following:

    command="/usr/sbin/cert_receive.py",no-agent-forwarding,no-port-forwarding,no-pty,no-X11-forwarding <key-type> <public-key> <comment>

Details on how `cert_receive.py` should validate and install certificates
and keys are specified in its configuration file, `/etc/cert_receive.json`.

## cert\_receive.py Invocation Protocol

When invoked, `cert_receive.py` expects to read the following from its
standard input stream:

1. A *config_name* identifying the certificates/key that are being provided,
   followed by a line separator.  The configuration name will be interpreted
   as UTF-8 characters.
2. A sequence of PEM-encoded certificate and private key blocks.  At least
   one certificate block must be provided.  At most one private key block
   may be provided.

## certbot\_send.sh

The `certbot_send.sh` script expects to be invoked with a `RENEWED_LINEAGE`
environment variable set to a directory containing certificate and key data.
Within that directory, the full chain of certificates (i.e., the service's
certificate as well as any intermediate certificates needed to validate to a
well-known CA) should exist in a file named `fullchain.pem`.  The private
key should exist in a file named `privkey.pem`.  If `certbot` is configured
to invoke `certbot_send.sh` as a deploy hook, `certbot` will set
`RENEWED_LINEAGE` and populate the directory appropriately.

The final path component of `RENEWED_LINEAGE` is considered the
*config_name* for the certificate and key data.  When `certbot_send.sh` is
invoked without any command line options, it will read configuration
directives first from `/etc/certbot_send/default` and then from
`/etc/certbot_send/`*`config_name`*`.conf`.  The *config_name* is also
provided to any `cert_receive.py` processes invoked on other hosts.
