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

Section TBD of [I-D.ietf-trans-rfc6962-bis] proposes two mechanisms for dealing
with this conundrum: wildcard certificates and name-constrained intermediate
CAs. However, these mechanisms are insufficient to cover all use cases.

TODO(eranm): Expand on when each of the other mechanisms is suitable and when
this mechanism may be suitable.

We define a domain label redaction mechanism that covers all use cases, at the
cost of increased implementation complexity. CAs and domain owners should note
that there are privacy considerations ({{privacy_considerations}}) and that
TLS clients may apply additional requirements (relating to the use of this
redaction mechanism) for a certificate to be considered compliant.

# Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC2119].

# Redacting Labels in Precertificates    {#redacting_labels}

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

# redactedSubjectAltName Certificate Extension    {#redacted_san_extension}

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
Name Constraints (section TBD of [I-D.ietf-trans-rfc6962-bis]) to allow DNS
domain name labels in other subjectAltName entries to not appear in logs.

TODO: Should we support redaction of SRV-IDs and URI-IDs using this mechanism?

# Verifying the redactedSubjectAltName extension    {#verifying_redacted_san}

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

# Reconstructing the TBSCertificate    {#reconstructing_tbscertificate}

Section TBD of [I-D.ietf-trans-rfc6962-bis] describes how TLS clients can
reconstruct the TBSCertificate component of a precertificate from a certificate,
so that associated SCTs may be verified.

If the redactedSubjectAltName extension ({{redacted_san_extension}}) is present
in the certificate, TLS clients MUST also:

* Verify the redactedSubjectAltName extension against the subjectAltName
  extension according to {{verifying_redacted_san}}.
* Once verified, remove the subjectAltName extension from the TBSCertificate.

# Security Considerations

## Avoiding Overly Redacting Domain Name Labels

Redaction of domain name labels carries the same risks as the use of wildcards
(e.g., section 7.2 of [RFC6125]). If the entirety of the domain space below the
unredacted part of a domain name is not registered by a single domain owner
(e.g., REDACT(label).com, REDACT(label).co.uk and other [Public.Suffix.List]
entries), then the domain name may be considered by clients to be overly
redacted.

CAs should take care to avoid overly redacting domain names in precertificates.
It is expected that monitors will treat precertificates that contain overly
redacted domain names as potentially misissued. TLS clients MAY consider a
certificate to be non-compliant if the reconstructed TBSCertificate
({{reconstructing_tbscertificate}}) contains any overly redacted domain names.
      
# Privacy Considerations    {#privacy_considerations}

## Ensuring Effective Redaction

Although the domain label redaction mechanism removes the need for private
labels to appear in logs, it does not guarantee that this will never happen.
Anyone who encounters a certificate could choose to submit it to one or more
logs, thereby rendering the redaction futile.

Domain owners are advised to take the following steps to minimize the likelihood
that their private labels will become known outside their closed communities:

* Avoid registering private labels in public DNS.
* Avoid using private labels that are predictable (e.g., "www", labels
  consisting only of numerical digits, etc). If a label has insufficient entropy
  then redaction will only provide a thin layer of obfuscation, because it will
  be feasible to recover the label via a brute-force attack.
* Avoid using publicly trusted certificates to secure private domain space.

CAs are advised to carefully consider each request to redact a label. When a CA
believes that redacting a particular label would be futile, we advise rejecting
the redaction request. TLS clients may have policies that forbid redaction, so
redaction should only be used when it's absolutely necessary and likely to be
effective.

# Acknowledgements

The authors would like to thank Andrew Ayer and TBD for their valuable
contributions.

A big thank you to Symantec for kindly donating the OID from the 1.3.101 arc
that is used in this document.
