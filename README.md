# ipsec-tools / racoon

A maintained Linux-focused continuation of the historical ipsec-tools project.

## Overview

ipsec-tools provides:

* `racoon` – IKEv1 key management daemon  
* `setkey` – PF\_KEY/IPsec Security Association management utility  
* `libipsec` – user-space IPsec support library

The project implements the Internet Key Exchange version 1 (IKEv1) protocol used to establish and manage IPsec VPN tunnels.

Although IKEv2 has largely superseded IKEv1 for new deployments, IKEv1 remains necessary for interoperability with legacy VPN infrastructure, embedded systems, industrial equipment, and Apple's built-in Cisco IPSec VPN compatibility mode.

## Why This Repository Exists

The original ipsec-tools project was hosted on SourceForge and is no longer actively maintained.

At the same time, a significant installed base of systems continues to depend on racoon and IKEv1 interoperability.

This repository serves as a Linux-focused continuation project with the following goals:

* Keep racoon buildable on modern Linux distributions.  
* Maintain compatibility with current compiler toolchains.  
* Maintain compatibility with current OpenSSL releases.  
* Maintain interoperability with Apple and Cisco-compatible clients.  
* Incorporate correctness, portability, and security fixes where practical.

Changes from NetBSD and other surviving descendants are periodically reviewed and incorporated where appropriate.

## Project Scope

This project intentionally focuses on maintenance and interoperability.

### Included

* Modern Linux support  
* OpenSSL 3.x support  
* Current compiler support  
* Bug fixes  
* Security fixes  
* Apple interoperability improvements  
* Packaging improvements

### Not Planned

* IKEv2 implementation  
* MOBIKE  
* EAP authentication  
* Plugin architecture  
* Major architectural redesigns  
* Feature parity with strongSwan or Libreswan

## Current Status

This project is actively maintained.

Recent work includes:

* OpenSSL 3.x compatibility updates  
* Modern compiler compatibility fixes  
* RFC 4868 interoperability improvements  
* Apple client interoperability fixes  
* Build system maintenance  
* Packaging improvements for modern Linux distributions

## Supported Platforms

Primary support targets:

| Platform | Status |
| :---- | :---- |
| Debian 12+ | Supported |
| Ubuntu 22.04+ | Supported |
| Ubuntu 24.04+ | Supported |
| Ubuntu 26.04+ | Supported |
| RHEL-compatible distributions | Best effort |
| Fedora | Best effort |

NetBSD and FreeBSD maintain their own versions and are outside the support scope of this repository.

## Quick Build

Build dependencies vary by distribution.

Typical build sequence:

```shell
autoreconf -fi
./configure
make
make check
sudo make install
```

LDAP support may be enabled with:

```shell
./configure --with-libldap
```

See the Administrator's Guide for detailed build and deployment instructions.

## Authentication Backends

racoon currently supports:

| Backend | Status |
| :---- | :---- |
| LDAP | Recommended |
| RADIUS | Legacy / lightly maintained |

LDAP can be used for:

* XAUTH user authentication  
* Per-user Mode Config address assignment  
* Integration with Samba Active Directory

Detailed configuration examples are available in the Administrator's Guide.

## Apple Compatibility

This continuation project includes interoperability fixes for Apple's Cisco IPSec implementation.

Apple continues to ship VPN functionality derived from the historical racoon codebase for compatibility with Cisco IPSec and L2TP/IPsec VPN connections.

Detailed guidance for:

* PKCS\#12 generation  
* Certificate requirements  
* mobileconfig deployment  
* Apple interoperability

is available in the Administrator's Guide.

## Security Considerations

racoon implements IKEv1, a mature but aging protocol.

New VPN deployments should generally prefer IKEv2-based solutions such as strongSwan or Libreswan.

In particular:

* Aggressive Mode with pre-shared keys is vulnerable to offline dictionary attacks.  
* Weak Diffie-Hellman groups should be avoided.  
* Legacy cryptographic algorithms should be disabled where possible.

This project focuses on maintaining secure operation within the constraints of the IKEv1 protocol.

## Alternatives

For new deployments consider:

* strongSwan  
* Libreswan  
* OpenIKED

These projects provide modern IKEv2 functionality and are actively developed.

racoon remains useful when interoperability with existing IKEv1 deployments is required.

## Documentation

* Administrator's Guide  
* Migration Guide  
* Release Notes  
* Historical ipsec-tools documentation

## Contributing

Bug reports, portability fixes, interoperability improvements, and documentation contributions are welcome.

Please include:

* Distribution and version  
* Compiler version  
* OpenSSL version  
* Relevant configuration excerpts  
* Log output when reporting issues

## License

See the LICENSE file for licensing information.  
