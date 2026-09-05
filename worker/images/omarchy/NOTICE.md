The Omarchy signing key in this directory comes from
`omacom/omarchy-pkgs/pkgbuilds/omarchy-keyring/omarchy.gpg` at commit
`99234a4fbb61b46225b2e9e560e114fbfebe8a95`.

Its fingerprint is
`40DFB630FF42BCFFB047046CF0134EE680CAC571`. The Dockerfile imports this
public key only to verify the signed `omarchy-keyring` package before the
repository keyring becomes active.

The upstream repository is available at
https://github.com/omacom/omarchy-pkgs and is distributed under the MIT
license. This profile does not copy its build scripts.
