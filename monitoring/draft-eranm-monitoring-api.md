---
title: "A RESTful API for Certificate Transparency Monitors"
docname: draft-eranm-monitoring-api
category: "exp"

ipr: "trust200902"
area: Security
wg: TRANS (Public Notary Transparency)

stand_alone: yes
smart_quotes: off
pi: [toc, sortrefs, symrefs]

author:
 -
    name: Eran Messeri
    org: Google UK Ltd.
    abbrev: Google
    email: eranm@google.com
 -
    name: Rob Stradling
    org: Comodo CA, Ltd.
    abbrev: Comodo
    email: rob.stradling@comodo.com

normative:
  RFC2119:
  RFC4627:
  RFC4648:
  RFC5246:
  RFC5280:
  RFC5652:
  RFC5905:
  RFC6066:
  RFC6125:
  RFC6960:
  RFC6961:
  RFC6979:
  RFC7633:
  RFC7924:

informative:
  RFC6962:

--- abstract

TODO: Proper abstract.

--- middle

# Introduction

TODO: Adopt introduction from Matt & Rob's draft or write a new one.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119 [RFC2119].

## Data Structures

Data structures are defined according to the conventions laid out in Section 4
of [RFC5246].

# Monitor operation
TODO: Describe how monitors are expected to operate, in terms of ingesting data from
logs. Refer to relevant sections in RFC6962-bis.

# Monitor Messages

These are APIs monitors SHOULD implement.

Note Logs MAY implement these messages. They are not required for correct operation
of logs, but may be convenient in some circumstances.

## Get Entry Number for SCT

GET https://\<server>/ct/v2/get-entry-for-sct

Inputs:

: sct:
  : A base64 encoded `TransItem` of type `x509_sct_v2` or `precert_sct_v2`
    signed by this log.
: log_id:
  : Optional, An OID of the log the query refers to.

Outputs:

: log_entries
  : An array of objects, each consisting of
    : log_id:
      : OID of the origin log for this entry.
    : entry:
      : 0-based index of the log entry corresponding to the supplied SCT.

Error codes:

|---------------+--------------------------------------------------------------------|
| Error Code    | Meaning                                                            |
|---------------+--------------------------------------------------------------------|
| bad signature | `sct` is not signed by this log.                                   |
| not found     | `sct` does not correspond to an entry that is currently available. |
|---------------+--------------------------------------------------------------------|

Note that any SCT signed by a log must have a corresponding entry in the log,
but it may not be retrievable until the MMD has passed since the SCT was issued.

If the log_id input parameter is ommitted, the log SHALL return entries from all
the logs it currently monitors.

## Get Entry Numbers for TBSCertificate

GET https://\<server>/ct/v2/get-entry-for-tbscertificate

Inputs:

: hash:
  : A base64 encoded HASH of a `TBSCertificate` for which the log has previously
    issued an SCT. (Note that a precertificate's TBSCertificate is reconstructed
    from the corresponding certificate as described in
    reconstructing_tbscertificate).
: log_id:
  : Optional, An OID of the log the query refers to.

Outputs:

: log_entries:
  : An array of objects, each consisting of
    : log_id:
      : OID of the origin log for this entry.
    :entries
      : An array of 0-based indices of log entries corresponding to the supplied
    HASH.

Error codes:

|------------+--------------------------------------------------------------------|
| Error Code | Meaning                                                            |
|------------+--------------------------------------------------------------------|
| bad hash   | `hash` is not the right size or format.                            |
| not found  | `sct` does not correspond to an entry that is currently available. |
|------------+--------------------------------------------------------------------|

Note that it is possible for a certificate to be logged more than once. If that
is the case, the monitor SHALL return all the indices it knows about for this
entry. If the certificate is present in the log, then the monitor MUST return at
least one entry index.

If the log_id input parameter is ommitted, the log SHALL return entries from all
the logs it currently monitors.

## Retrieve Signed Tree Heads between Two Times
GET https://\<server>/ct/v2/get-sths

Inputs:

: start:
  : an earlier NTP Time [RFC5905], measured in milliseconds since the epoch (January 1, 1970, 00:00 UTC), ignoring leap seconds.

: end:
  : a later NTP Time [RFC5905], measured in milliseconds since the epoch (January 1, 1970, 00:00 UTC), ignoring leap seconds.

: log_id:
  : OID of the log this request refers to.

Outputs:

: log_sths:
  : An array of objects, each consisting of
    : log_id : OID of the log which issued the STHs.
    : sths: : an array of base64 encoded TransItem structures of type signed_tree_head_v2, signed by this log.

The start and end parameters SHOULD be within the range 0 <= x < timestamp as returned by get-sth.

The start parameter MUST be less than or equal to the end parameter.

Servers MUST honor requests where 0 <= start < timestamp and end >= timestamp by returning a partial response covering only the STHs in the specified range. end >= timestamp could be caused by skew. Note that the following restriction may also apply:

Servers MAY restrict the number of STHs that can be retrieved per get-sths request. If there are more than the permitted number of STHs in the specified range, the log SHALL return the maximum number of STHs permissible. These STHs SHALL be ordered chronologically by timestamp, oldest first, beginning with the earliest STH in the specified range.

It is possible the server will not have any STHs between start and end. In this case it MUST return an empty sths array.

When implemented by a log, the log_id parameter SHALL be ommitted by clients and ignored by the log.

--- back

# Monitoring V1 and V2 logs concurrently

Does it make sense for monitors to monitor V1 and V2 logs at the same time?
TODO(eranm): Think about a schema for combining replies, if sensible.
