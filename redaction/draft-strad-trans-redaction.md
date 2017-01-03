---
title: "Certificate Transparency: Domain Label Redaction"
docname: draft-strad-trans-redaction-01
abbrev: CT Domain Label Redaction
category: exp

ipr: trust200902
area: Security
wg: TRANS (Public Notary Transparency)
kw: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: R. Stradling
    name: Rob Stradling
    org: Comodo CA, Ltd.
    email: rob.stradling@comodo.com
 -
    ins: E. Messeri
    name: Eran Messeri
    org: Google UK Ltd.
    email: eranm@google.com

normative:
  RFC2119:
  RFC4648:
  RFC5280:
  RFC6125:
  I-D.ietf-trans-rfc6962-bis:

informative:
  EV.Certificate.Guidelines:
    target: https://cabforum.org/wp-content/uploads/EV_Certificate_Guidelines.pdf
    title: Guidelines For The Issuance And Management Of Extended Validation Certificates
    author:
      org: CA/Browser Forum
    date: 2007
  Public.Suffix.List:
    target: https://publicsuffix.org
    title: Public Suffix List
    author:
      org: Mozilla Foundation
    date: 2016

--- abstract

This document defines mechanisms to allow DNS domain name labels that are
considered to be private to not appear in public Certificate Transparency (CT)
logs, while still retaining most of the security benefits that accrue from using
Certificate Transparency.

--- middle

# Introduction

Some domain owners regard certain DNS domain name labels within their registered
domain space as private and security sensitive. Even though these domains are
often only accessible within the domain owner's private network, it's common for
them to be secured using publicly trusted Transport Layer Security (TLS) server
certificates.

Certificate Transparency [I-D.ietf-trans-rfc6962-bis] describes a protocol for
publicly logging the existence of TLS server certificates as they are issued or
observed. Since each TLS server certificate lists the domain names that it is
intended to secure, private domain name labels within registered domain space
could end up appearing in CT logs, especially as TLS clients develop policies
that mandate CT compliance. This seems like an unfortunate and potentially
unnecessary privacy leak, because it's the registered domain names in each
certificate that are of primary interest when using CT to look for suspect
certificates.

TODO: Highlight better the differences between registered domains and
subdomains, referencing the relevant DNS RFCs.

# Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC2119].

# Redaction Mechanisms

We propose three mechanisms, in increasing order of implementation complexity,
to allow certain DNS domain name labels to not appear in public CT logs:

* Using wildcard certificates ({{wildcard_certificates}}) is the simplest
  option, but it only covers certain use cases.

* Logging a name-constrained intermediate CA certificate in place of the
  end-entity certificate ({{name_constrained}}) covers more, but not all, use
  cases.

* Therefore, we define a domain label redaction mechanism ({{redacting_labels}})
  that covers all use cases, at the cost of considerably increased
  implementation complexity.

We anticipate that TLS clients may develop policies that impose additional
compliancy requirements on the use of the {{name_constrained}} and
{{redacting_labels}} mechanisms.

To ensure effective redaction, CAs and domain owners should note the privacy
considerations ({{privacy_considerations}}).

TODO(eranm): Do we need to further expand (either here or in the following
subsections) on when each of the mechanisms is/isn't suitable?

## Using Wildcard Certificates    {#wildcard_certificates}

A certificate containing a DNS-ID [RFC6125] of `*.example.com` could be used to
secure the domain `topsecret.example.com`, without revealing the label
`topsecret` publicly.

Since TLS clients only match the wildcard character to the complete leftmost
label of the DNS domain name (see Section 6.4.3 of [RFC6125]), a different
mechanism is needed when any label other than the leftmost label in a DNS-ID is
considered private (e.g., `top.secret.example.com`). Also, wildcard certificates
are prohibited in some cases, such as Extended Validation Certificates
[EV.Certificate.Guidelines].

## Using a Name-Constrained Intermediate CA    {#name_constrained}

An intermediate CA certificate or intermediate CA precertificate that contains
the Name Constraints [RFC5280] extension MAY be logged in place of end-entity
certificates issued by that intermediate CA, as long as all of the following
conditions are met:

* there MUST be a non-critical extension (OID 1.3.101.76, whose extnValue OCTET
  STRING contains ASN.1 NULL data (0x05 0x00)). This extension is an explicit
  indication that it is acceptable to not log certificates issued by this
  intermediate CA.

* there MUST be a Name Constraints extension, in which:

  * permittedSubtrees MUST specify one or more dNSNames.

  * excludedSubtrees MUST specify the entire IPv4 and IPv6 address ranges.

Below is an example Name Constraints extension that meets these conditions:

~~~~~~~~~~~
    SEQUENCE {
      OBJECT IDENTIFIER '2 5 29 30'
      BOOLEAN TRUE
      OCTET STRING, encapsulates {
        SEQUENCE {
          [0] {
            SEQUENCE {
              [2] 'example.com'
              }
            }
          [1] {
            SEQUENCE {
              [7] 00 00 00 00 00 00 00 00
              }
            SEQUENCE {
              [7]
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
              }
            }
          }
        }
      }
~~~~~~~~~~~

### Presenting SCTs, Inclusion Proofs and STHs

Each SCT (and optional corresponding inclusion proof and STH) presented by a TLS
server MAY correspond to an intermediate CA certificate or intermediate CA
precertificate (to which the server certificate chains) that meets the
requirements in {{name_constrained}}. This extends section TBD of CT v2
[I-D.ietf-trans-rfc6962-bis], which specifies that each SCT always corresponds
to the server certificate or to a precertificate that corresponds to that
certificate.

Each SCT (and optional corresponding inclusion proof and STH) included by a
certification authority in a Transparency Information X.509v3 extension in the
`singleExtensions` of a `SingleResponse` in an OCSP response MAY correspond to
an intermediate CA certificate or intermediate CA precertificate (to which the
certificate identified by the `certID` of that `SingleResponse` chains) that
meets the requirements in {{name_constrained}}. This extends section TBD of CT
v2 [I-D.ietf-trans-rfc6962-bis], which specifies that each SCT always
corresponds to the certificate identified by the `certID` of that
`SingleResponse` or to a precertificate that corresponds to that certificate.

Each SCT (and optional corresponding inclusion proof and STH) included by a
certification authority in a Transparency Information X.509v3 extension in a
certificate MAY correspond to an intermediate CA certificate or intermediate CA
precertificate (to which the certificate chains) that meets the requirements in
{{name_constrained}}. This extends section TBD of CT v2
[I-D.ietf-trans-rfc6962-bis], which specifies that each SCT always corresponds
to a precertificate that corresponds to that certificate.

### Matching an SCT to the Correct Certificate

Before considering any SCT to be invalid, a TLS client MUST attempt to validate
it against the server certificate and against each of the zero or more suitable
name-constrained intermediates in the chain. These certificates may be evaluated
in the order they appear in the chain, or indeed, in any order.

## Redacting Labels in Precertificates    {#redacting_labels}

When creating a precertificate, the CA MAY include a redactedSubjectAltName
({{redacted_san_extension}}) extension that contains, in a redacted form,
the same entries that will be included in the certificate's subjectAltName
extension. When the redactedSubjectAltName extension is present in a
precertificate, the subjectAltName extension MUST be omitted (even though it
MUST be present in the corresponding certificate).

Wildcard `*` labels MUST NOT be redacted, but one or more non-wildcard labels in
each DNS-ID [RFC6125] can each be replaced with a redacted label as follows:

~~~~~~~~~~~
  REDACT(label) = prefix || BASE32(index || _label_hash)
    _label_hash = LABELHASH(keyid_len || keyid || label_len || label)
~~~~~~~~~~~

`label` is the case-sensitive label to be redacted.

`prefix` is the "?" character (ASCII value 63).

`index` is the 1 byte index of a hash function in the CT hash algorithm registry
(section TBD of [I-D.ietf-trans-rfc6962-bis]). The value 255 is reserved.

`keyid_len` is the 1 byte length of the `keyid`.

`keyid` is the keyIdentifier from the Subject Key Identifier extension
(section 4.2.1.2 of [RFC5280]), excluding the ASN.1 OCTET STRING tag and length
bytes.

`label_len` is the 1 byte length of the `label`.

`||` denotes concatenation.

`BASE32` is the Base 32 Encoding function (section 6 of [RFC4648]). Pad
characters MUST NOT be appended to the encoded data.

`LABELHASH` is the hash function identified by `index`.

### redactedSubjectAltName Certificate Extension    {#redacted_san_extension}

The redactedSubjectAltName extension is a non-critical extension
(OID 1.3.101.77) that is identical in structure to the subjectAltName extension,
except that DNS-IDs MAY contain redacted labels ({{redacting_labels}}).

When used, the redactedSubjectAltName extension MUST be present in both the
precertificate and the corresponding certificate.

This extension informs TLS clients of the DNS-ID labels that were redacted and
the degree of redaction, while minimizing the complexity of TBSCertificate
reconstruction ({{reconstructing_tbscertificate}}). Hashing the redacted labels
allows the legitimate domain owner to identify whether or not each redacted
label correlates to a label they know of.

TODO: Consider the pros and cons of this 'un'redaction feature. If the cons
outweigh the pros, switch to using Andrew Ayer's alternative proposal of hashing
a random salt and including that salt in an extension in the certificate (and
not including the salt in the precertificate).

Only DNS-ID labels can be redacted using this mechanism. However, CAs can use
the {{name_constrained}} mechanism to allow DNS domain name labels in other
subjectAltName entries to not appear in logs.

TODO: Should we support redaction of SRV-IDs and URI-IDs using this mechanism?

### Verifying the redactedSubjectAltName extension    {#verifying_redacted_san}

If the redactedSubjectAltName extension is present, TLS clients MUST check that
the subjectAltName extension is present, that the subjectAltName extension
contains the same number of entries as the redactedSubjectAltName extension, and
that each entry in the subjectAltName extension has a matching entry at the same
position in the redactedSubjectAltName extension. Two entries are matching if
either:

* The two entries are identical; or
* Both entries are DNS-IDs, have the same number of labels, and each label in
  the subjectAltName entry has a matching label at the same position in the
  redactedSubjectAltName entry. Two labels are matching if either:
  * The two labels are identical; or,
  * Neither label is `*` and the label from the redactedSubjectAltName entry is
    equal to REDACT(label from subjectAltName entry) ({{redacting_labels}}).

If any of these checks fail, the certificate MUST NOT be considered compliant.

### Reconstructing the TBSCertificate    {#reconstructing_tbscertificate}

Section TBD of [I-D.ietf-trans-rfc6962-bis] describes how TLS clients can
reconstruct the TBSCertificate component of a precertificate from a certificate,
so that associated SCTs may be verified.

If the redactedSubjectAltName extension ({{redacted_san_extension}}) is present
in the certificate, TLS clients MUST also:

* Verify the redactedSubjectAltName extension against the subjectAltName
  extension according to {{verifying_redacted_san}}.
* Once verified, remove the subjectAltName extension from the TBSCertificate.

# Security Considerations

## Avoiding Overly Redacted Domain Names

Redaction of domain name labels ({{redacting_labels}}) carries the same risks as
the use of wildcards (e.g., section 7.2 of [RFC6125]). If the entirety of the
domain space below the unredacted part of a domain name is not registered by a
single domain owner (e.g., REDACT(label).com, REDACT(label).co.uk and other
[Public.Suffix.List] entries), then the domain name may be considered by clients
to be overly redacted.

CAs should take care to avoid overly redacting domain names in precertificates.
It is expected that monitors will treat precertificates that contain overly
redacted domain names as potentially misissued. TLS clients MAY consider a
certificate to be non-compliant if the reconstructed TBSCertificate
({{reconstructing_tbscertificate}}) contains any overly redacted domain names.
      
# Privacy Considerations    {#privacy_considerations}

## Ensuring Effective Redaction

Although the mechanisms described in this document remove the need for private
labels to appear in CT logs, they do not guarantee that this will never happen.
For example, anyone who encounters a certificate could choose to submit it to
one or more logs, thereby rendering the redaction futile.

Domain owners are advised to take the following steps to minimize the likelihood
that their private labels will become known outside their closed communities:

* Avoid registering private labels in public DNS.
* Avoid using private labels that are predictable (e.g., "www", labels
  consisting only of numerical digits, etc). If a label has insufficient entropy
  then redaction will only provide a thin layer of obfuscation, because it will
  be feasible to recover the label via a brute-force attack.
* Avoid using publicly trusted certificates to secure private domain space.

CAs are advised to carefully consider each request to redact a label using the
{{redacting_labels}} mechanism. When a CA believes that redacting a particular
label would be futile, we advise rejecting the redaction request. TLS clients
may have policies that forbid redaction, so label redaction should only be used
when it's absolutely necessary and likely to be effective.

# Acknowledgements

The authors would like to thank Andrew Ayer and TBD for their valuable
contributions.

A big thank you to Symantec for kindly donating the OIDs from the 1.3.101 arc
that are used in this document.
