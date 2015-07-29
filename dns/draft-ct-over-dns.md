---
title: Certificate Transparency over DNS
docname: draft-ct-over-dns-01-dev
category: exp
pi: [toc, sortrefs, symrefs]
ipr: trust200902
area: Security
wg: TRANS
kw: Internet-Draft

author:
  -
    ins: B. Laurie
    name: Ben Laurie
    email: benl@google.com
    org: Google UK Ltd.
  -
    ins: P. Phaneuf
    name: Pierre Phaneuf
    email: pphaneuf@google.com
    org: Google UK Ltd.
  -
    ins: A. Eijdenberg
    name: Adam Eijdenberg
    email: eijdenberg@google.com
    org: Google Inc.

normative:
  RFC6962:
  RFC1035:
  RFC4648:

informative:
  RFC1034:

--- abstract

We describe a method for fetching certificate transparency inclusion proofs over recursive DNS.

--- middle

# Introduction

Certificate Transparency improves the certificate ecosystem by requiring certificates be submitted to logs in order to be considered secure.  To prove that a certificate has been included in a public log clients should request inclusion proofs from logs as descrbed in RFC6962.

However by fetching an inclusion proof directly from a log server the client reveals to the log server the certificate that they are interested in, and thus leaks their browsing history.

This document describes the use of special DNS records so that a client can look up certificate transparency information via their existing DNS resolver, meaning that they will identify their browsing history to only their existing DNS resolver (typically at their ISP), which, in most cases, already knows which sites the user has visited by virtue of having resolved their DNS requests already.

In this manner only a proxy for aggregate usage of sites contained in a log will be detectable by the log operator or mirror that operates the authoritative name server used by these resolvers.

Google plans to operate such a DNS resolver to put in front of log mirrors for at least all logs included by Chrome.  Other clients are welcome to use the same name servers if desired.

# Overview

...

# Messages
A log operator or mirror conforming with this specification SHALL provide a name server that provides authoritative answers to the following types of queries.

## STH Query

TODO

## Hash Query

Inputs:
: 
: `domain_for_log` is a value stored in log metadata.  For example, a name server operated by Google for the Pilot log may have the domain `pilot.ct.googleapis.com`.

: `leaf_hash` is the a leaf hash as defined in section 3.4 of RFC6962.

Outputs:
: 
: `leaf_index` is the index of the `leaf_hash` in the Merkle tree.


To query for this message, set `QNAME` to `<encoded_leaf_hash> || '.hash.' || <domain_for_log> || '.'`

`encoded_leaf_hash` is the base32 encoding of `leaf_hash`.  For example, given a `MerkleTreeLeaf` structure represented as the concentation of:

    0x00               (v1)
    0x00               (timestamped_entry)
    0x0001020304050607 (timestamp)
    0x0000             (x509_entry)
    0x000001           (length of ASN.1 Cert)
    0x00               (bogus ASN.1 Cert)
    0x0000             (extensions length)


Then the `encoded_leaf_hash` would be:

    D4S6DSV2J743QJZEQMH4UYHEYK7KRQ5JIQOCPMFUHZVJNFGHXACA====

Since the length is known, a client MAY omit the 4 padding byte suffix.

Given the `encoded_leaf_hash` above we would generate the following request:

               +---------------------------------------------------+
    Header     | OPCODE=SQUERY                                     |
               +---------------------------------------------------+
    Question   | QNAME=D4S6DSV2J743QJZEQMH4UYHEYK7KRQ5JIQOCPMFUHZVJ|
               | NFGHXACA.hash.pilot.ct.googleapis.com., QCLASS=IN,|
               | QTYPE=TXT                                         |
               +---------------------------------------------------+
    Answer     | <empty>                                           |
               +---------------------------------------------------+
    Authority  | <empty>                                           |
               +---------------------------------------------------+
    Additional | <empty>                                           |
               +---------------------------------------------------+

And receive the following response:

               +---------------------------------------------------+
    Header     | OPCODE=SQUERY, RESPONSE, AA                       |
               +---------------------------------------------------+
    Question   | QNAME=D4<snip>.com., QCLASS=IN, QTYPE=TXT         |
               +---------------------------------------------------+
    Answer     | QNAME=D4<snip>.com., 604800 IN TXT 123456         |
               +---------------------------------------------------+
    Authority  | <empty>                                           |
               +---------------------------------------------------+
    Additional | <empty>                                           |
               +---------------------------------------------------+

The TXT record indicates in ASCII decimal the `leaf_index` of the `leaf_hash` in the log.  In this example the `leaf_index` is `123456`.


## Tree Query

The tree query takes as input:

- `domain_for_log`
- `start_index`
- `leaf_index`
- `tree_size`

And returns as output:

- `partial_audit_path[]`

Set `QNAME` to `<i> || '.' || <leaf_index> || '.' || <tree_size> || '.tree.' || <domain_for_log> || '.'`

For example, given the values above we would generate the following request:

               +---------------------------------------------------+
    Header     | OPCODE=SQUERY                                     |
               +---------------------------------------------------+
    Question   | QNAME=0.123456.999999.tree.pilot.ct.googleapis.com|
               | ., QCLASS=IN, QTYPE=TXT                           |
               +---------------------------------------------------+
    Answer     | <empty>                                           |
               +---------------------------------------------------+
    Authority  | <empty>                                           |
               +---------------------------------------------------+
    Additional | <empty>                                           |
               +---------------------------------------------------+

And receive the following response:

               +---------------------------------------------------+
    Header     | OPCODE=SQUERY, RESPONSE, AA                       |
               +---------------------------------------------------+
    Question   | QNAME=0.<snip>.com., QCLASS=IN, QTYPE=TXT         |
               +---------------------------------------------------+
    Answer     | QNAME=0.<snip>.com., 604800 IN TXT                |
               | <character-string for BASE64(audit_path[0])>      |
               | <character-string for BASE64(audit_path[1])>      |
               | <character-string for BASE64(audit_path[2])>      |
               | ...                                               |
               +---------------------------------------------------+
    Authority  | <empty>                                           |
               +---------------------------------------------------+
    Additional | <empty>                                           |
               +---------------------------------------------------+

Where the TXT RDATA returned will be one or more character-strings, each containing the BASE64 encoding of the value for next value in the `audit_path` array.  Note that the first character-string will be for the number specified in the query, and the server MAY return one or more subsequent values that correspond to the next values in the array.  Since the size of DNS responses is limited, servers MAY not return all values for `audit_path` in a single query, and if the correct number (`length`) of response is not returned, a client MUST send a subsequent query with a different starting index until all elements are accounted for.


# How to use the messages
 

## Retrieve Merkle Audit Proof from Log by Leaf Hash

(equivalent to RFC6962 Section 4.5)

Set `encoded_leaf_hash` to `BASE32(SHA-256(0x00 || MerkleTreeLeaf)`.

For example, 

Set `domain_for_log` to a value stored in your log metadata.  For example, a name server operated by Google for the Pilot log may have the domain `pilot.ct.googleapis.com`.

Set `QNAME` to `<encoded_leaf_hash> || '.hash.' || <domain_for_log> || '.'`

For example, given the `encoded_leaf_hash` above we would generate the following request:

               +---------------------------------------------------+
    Header     | OPCODE=SQUERY                                     |
               +---------------------------------------------------+
    Question   | QNAME=D4S6DSV2J743QJZEQMH4UYHEYK7KRQ5JIQOCPMFUHZVJ|
               | NFGHXACA.hash.pilot.ct.googleapis.com., QCLASS=IN,|
               | QTYPE=TXT                                         |
               +---------------------------------------------------+
    Answer     | <empty>                                           |
               +---------------------------------------------------+
    Authority  | <empty>                                           |
               +---------------------------------------------------+
    Additional | <empty>                                           |
               +---------------------------------------------------+

And receive the following response:

               +---------------------------------------------------+
    Header     | OPCODE=SQUERY, RESPONSE, AA                       |
               +---------------------------------------------------+
    Question   | QNAME=D4<snip>.com., QCLASS=IN, QTYPE=TXT         |
               +---------------------------------------------------+
    Answer     | QNAME=D4<snip>.com., 604800 IN TXT 123456         |
               +---------------------------------------------------+
    Authority  | <empty>                                           |
               +---------------------------------------------------+
    Additional | <empty>                                           |
               +---------------------------------------------------+

The TXT record indicates in ASCII decimal the index of the leaf entry in the log. This corresponds to `leaf_index` as returned by `/ct/v1/get-proof-by-hash`.

In this example the `leaf_index` is `123456`.

We use this in follow-up DNS lookups needed to retrieve the `audit_path`.  Specifically we need to perform one query for each entry in the `audit_path` array.

First, we must calculate the length of the `audit_path` array.  This is calculated as a function of the `leaf_index` and the `tree_size` for which the inclusion proof is based.

1. Set `length` to `0`, `ln` to `tree_size - 1` and `li` to `leaf_index`.
2. While `ln` is not `0`:
    1. If `LSB(li)` is set, or if `li < ln1`, then increment `length`.
    2. Right-shift both `li` and `ln` one bit.
3. `length` now represents the number of elements needed for the `audit_path` array.

Now, for each value `i` from `0` to `length - 1` we can make the following query to retrieve the proof that element of the `audit_path` array:

Set `QNAME` to `<i> || '.' || <leaf_index> || '.' || <tree_size> || '.tree.' || <domain_for_log> || '.'`

For example, given the values above we would generate the following request:

               +---------------------------------------------------+
    Header     | OPCODE=SQUERY                                     |
               +---------------------------------------------------+
    Question   | QNAME=0.123456.999999.tree.pilot.ct.googleapis.com|
               | ., QCLASS=IN, QTYPE=TXT                           |
               +---------------------------------------------------+
    Answer     | <empty>                                           |
               +---------------------------------------------------+
    Authority  | <empty>                                           |
               +---------------------------------------------------+
    Additional | <empty>                                           |
               +---------------------------------------------------+

And receive the following response:

               +---------------------------------------------------+
    Header     | OPCODE=SQUERY, RESPONSE, AA                       |
               +---------------------------------------------------+
    Question   | QNAME=0.<snip>.com., QCLASS=IN, QTYPE=TXT         |
               +---------------------------------------------------+
    Answer     | QNAME=0.<snip>.com., 604800 IN TXT                |
               | <character-string for BASE64(audit_path[0])>      |
               | <character-string for BASE64(audit_path[1])>      |
               | <character-string for BASE64(audit_path[2])>      |
               | ...                                               |
               +---------------------------------------------------+
    Authority  | <empty>                                           |
               +---------------------------------------------------+
    Additional | <empty>                                           |
               +---------------------------------------------------+

Where the TXT RDATA returned will be one or more character-strings, each containing the BASE64 encoding of the value for next value in the `audit_path` array.  Note that the first character-string will be for the number specified in the query, and the server MAY return one or more subsequent values that correspond to the next values in the array.  Since the size of DNS responses is limited, servers MAY not return all values for `audit_path` in a single query, and if the correct number (`length`) of response is not returned, a client MUST send a subsequent query with a different starting index until all elements are accounted for.


# IANA considerations

TBD

# Contributors

The authors would like to thank the following contributors for
valuable suggestions: ...

# ChangeLog
