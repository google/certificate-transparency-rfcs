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

We describe a method for fetching Certificate Transparency inclusion proofs over recursive DNS.

--- middle

# Introduction

Certificate Transparency improves the certificate ecosystem by requiring certificates be submitted to logs in order to be considered secure.  To prove that a certificate has been included in a public log clients should request inclusion proofs from logs as descrbed in {{RFC6962}}.

However by fetching an inclusion proof directly from a log server the client reveals to the log server the certificate that they are interested in, and thus leaks their browsing history.

This document describes the use of special DNS records so that a client can look up Certificate Transparency information via their existing DNS resolver, meaning that they will identify their browsing history to only their existing DNS resolver (typically at their ISP), which, in most cases, already knows which sites the user has visited by virtue of having resolved their DNS requests already.

In this manner only a proxy for aggregate usage of sites contained in a log will be detectable by the log operator or mirror that operates the authoritative name server used by these resolvers.

# Overview

...

# Messages
A log operator or mirror conforming with this specification SHALL provide a name server that provides authoritative answers to the following types of queries.

## STH Query

TODO

## Hash Query {#hashquery}

Inputs:
:
: `domain_for_log` is a value stored in log metadata.  For example, a name server operated by Google for the Pilot log may have the domain `pilot.ct.googleapis.com`.

: `leaf_hash` is the a leaf hash as defined in section 3.4 of {{RFC6962}}.

Outputs:
:
: `leaf_index` is the index of the `leaf_hash` in the Merkle tree.


To query for this message, set `QNAME` to `<encoded_leaf_hash> || '.hash.' || <domain_for_log> || '.'` where `||` is concatenation

`encoded_leaf_hash` is the base32 encoding of `leaf_hash` without padding.  For example, given a `MerkleTreeLeaf` structure represented as the concentation of:

    0x00               (v1)
    0x00               (timestamped_entry)
    0x0001020304050607 (timestamp)
    0x0000             (x509_entry)
    0x000001           (length of ASN.1 Cert)
    0x00               (bogus ASN.1 Cert)
    0x0000             (extensions length)


Then the `encoded_leaf_hash` would be:

    D4S6DSV2J743QJZEQMH4UYHEYK7KRQ5JIQOCPMFUHZVJNFGHXACA

(Since the length is known, and `=` is not a legal domain name character, a client MUST omit the 4 padding byte suffix.)

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


## Tree Query {#treequery}

Inputs:
:
: `domain_for_log` is a value stored in log metadata.  For example, a name server operated by Google for the Pilot log may have the domain `pilot.ct.googleapis.com`.
: `start_index` is the index (starting from `0`) of the first entry of audit path desired.  This will be `0` for the first query and an offset amount in subsequent queries.
: `leaf_index` is the leaf index for which the audit path should be generated.
: `tree_size` is the tree size for which the audit path should be generated.

Outputs:
:
: `partial_audit_path` is an array of TODO.


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
               | <character-string for                             |
               |     audit_path[0] || ... ||  audit_path[n] >      |
               +---------------------------------------------------+
    Authority  | <empty>                                           |
               +---------------------------------------------------+
    Additional | <empty>                                           |
               +---------------------------------------------------+

Where the TXT RDATA returned will be exactly one character-string.  It contains binary data representing concatenated values from the `audit_path` array.  The first value will be for the number specified in the query, and the server MAY return one or more subsequent values that correspond to the next values in the array.  Since the size of DNS responses is limited, servers MAY not return all values for `audit_path` in a single query, and if the correct number (`length`) of response is not returned, a client MUST send a subsequent query with a different starting index until all elements are accounted for.

For example, if the underlying log uses SHA-256 for a hash function, the maximum number of values that can be returned is `7` (floor of `255` divided by `32`).


# How to use the messages


## Retrieve Merkle Audit Proof from Log by Leaf Hash

(equivalent to {{RFC6962}} section 4.5)

First, perform a Hash Query as defined in {{hashquery}} to calculate the `leaf_index`.

We use this in follow-up DNS lookups needed to retrieve the `audit_path`. Specifically we need to perform one or more queries to retrieve all values to populate the `audit_path` array.

First, we must calculate the length of the `audit_path` array.  This is calculated as a function of the `leaf_index` and the `tree_size` for which the inclusion proof is based.

1. Set `length` to `0`, `ln` to `tree_size - 1` and `li` to `leaf_index`.
2. While `ln` is not `0`:
    1. If `LSB(li)` is set, or if `li < ln`, then increment `length`.
    2. Right-shift both `li` and `ln` one bit.
3. `length` now represents the number of elements needed for the `audit_path` array.

Now that we know the length of the `audit_path` array, we can perform one or more Tree Queries (as defined in {{treequery}}) to retrieve elements to populate that array.

For example, given a `leaf_index` of `123456` and a `tree_size` of `999999` we calculate the length of the `audit_path` to be `20`.  We then perform a Tree Query for:

    0.123456.999999.tree.pilot.ct.googleapis.com

which may return up to `7` elements of the `audit_path`.  We perform a follow-up query for:

    7.123456.999999.tree.pilot.ct.googleapis.com

to retreive a next `partial_audit_path` offset by `7` and then:

    14.123456.999999.tree.pilot.ct.googleapis.com

to retreive the final `6`.

Now we have a complete `audit_path` array.


# IANA considerations

TBD

# Contributors

The authors would like to thank the following contributors for
valuable suggestions: ...

# ChangeLog
