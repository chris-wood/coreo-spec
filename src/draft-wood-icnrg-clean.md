---
title: Content-Locked Encryption and Authentication of Nameless Objects
abbrev: CCNxCLEAN
docname: draft-wood-icnrg-clean-latest
category: exp

ipr: pre5378Trust200902
area: General
workgroup: icnrg
keyword: Internet-Draft

stand_alone: yes
pi:
  rfcedstyle: yes
  toc: yes
  tocindent: yes
  sortrefs: yes
  symrefs: yes
  strict: yes
  comments: yes
  inline: yes
  text-list-symbols: -o*+

author:
-
    ins: C. A. Wood
    name: Christopher A. Wood
    organization: University of California Irvine
    email: woodc1@uci.edu

normative:
  RFC2119:
  RFC5869:
  CCNxSemantics:
    target: https://tools.ietf.org/html/draft-irtf-icnrg-ccnxsemantics-04
    title: "CCNx Semantics"
    author:
        -
            ins: M. Mosko
            org: PARC, Inc.
        -
            ins: I. Solis
            org: LinkedIn
        -
            ins: C. A. Wood
            org: University of California, Irvine
  FLIC:
    target: https://datatracker.ietf.org/doc/draft-tschudin-icnrg-flic/
    title: "File-Like ICN Collection (FLIC)"
    author:
        -
            ins: Christian Tschudin
            org: University of Basel
        -
            ins: Christopher A. Wood
            org: University of California Irvine
  CCNxKE:
    target: https://datatracker.ietf.org/doc/draft-wood-icnrg-ccnxkeyexchange/
    title: "CCNx Key Exchange Protocol Version 1.0"
    author:
        -
            ins: Marc Mosko
            org: PARC, Inc.
        -
            ins: Ersin Uzun
            org: PARC, Inc.
        -
            ins: Christopher A. Wood
            org: University of California, Irvine
  MLE:
    target: https://eprint.iacr.org/2012/631.pdf
    title: "Message-locked encryption and secure deduplication"
    author:
        -
            ins: Mihir Bellare
            org: University of California San Diego
        -
            ins: Sriram Keelveedhi
            org: University of California San Diego
        -
            ins: Thomas Ristenpart
            org: University of Wisconsin–Madison

<!-- informative: -->

--- abstract

This document specifies CCNx CLEAN -- content-locked encryption and
authentication of nameless objects -- as a way of enabling encrypted
and naturally de-duplicated content in CCN. CLEAN allows producers to
encrypt large collections of static data and use the FLIC Manifest
to convey the necessary decryption information to consumers. As a result,
CLEAN encrypts nameless content objects without any application input.

--- middle

#  Introduction

In CCN, nameless objects are content objects which do not carry a Name TLV field {{CCNxSemantics}}.
Matching an interest to a nameless content object therefore requires knowledge of the
latter's ContentObjectHash (or ContentId). A ContentId is the cryptographic
hash of a Content Object message. A router may only forward a nameless content
object if its cryptographic hash digest matches that which is specified in the
ContentObjectHashRestriction of the corresponding interest.

Manifests are network-level structures used to convey ContentIds to consumers so that
they may request nameless content objects. These are necessary since a consumer cannot
know the ContentId of a nameless content object which it has not yet retrieved.
Manifests are typically used to group segments of a single, large piece of data
under a common name. For example, imagine the consumer wishes to obtain the data named
/foo/bar, which has a total size well beyond the 64KiB limit imposed by the CCN packet
format. To transfer /foo/bar efficiently, the producer segments the /foo/bar data
into fixed size chunks and, for each chunk, creates a nameless content object. Then,
the producer creates a Manifest with the name /foo/bar which contains the references
to each of these constituent nameless object parts, along with their ContentIds.
To fetch /foo/bar, a consumer then (a) issues a request for the name /foo/bar, (b) receives,
verifies, and parses the Manifest, and (c) subsequently issues requests for each
nameless content object using the provided ContentIds. (See {{CCNxSemantics}} for more
details.) The {{FLIC}} data structure is one type of CCN Manifest data structure
used to enable this mechanism.

By default, the data contained inside each nameless content object is unencrypted.
If privacy is required, the producer application must explicitly encrypt
the data prior to transfer. This is not ideal since it requires application-layer
input. To improve this baseline scenario, we introduce CCNx CLEAN -- content-locked
encryption and authentication of nameless objects. CLEAN builds on recent advances in
message-locked encryption ({{MLE}}) to encrypt nameless objects by default without
invalidating their natural de-duplication properties.

##  Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 {{RFC2119}}.

The following terms are used:

Nameless object: A CCN content object packet which contain a Name TLV field.

# CLEAN Crypto

CLEAN only relies on MLE, which is a form of encryption by which the encryption key
for a message is derived from the message itself. For example, in MLE, a message M
may be encrypted by a key K = H(M), where H is a suitable cryptographic hash function
for use in MLE constructions. The encryption of M is thus computed as M' = Enc(H(M), M),
where Enc is a symmetric-key encryption algorithm suitable for MLE.
This procedure is deterministic; two identical messages will be encrypted to identical
ciphertext values. As a result, MLE supports natural de-duplication of data based on
ciphertext equality.

# CLEAN End Host Support

Let D be a piece of data for which a producer P would normally
create a Manifest with name N, i.e., M(N). Let C_1,...,C_n be the n nameless content
object *payloads* created from D. The CLEAN construction works as follows:

1. P computes k = KDF(H(D)), where KDF is a suitable key derivation function, such as HKDF {{RFC5869}}.

2. For each C_i in C_1,...,C_n, P derives k_i = KDF(k + i) uses it to compute C_i' = Enc(k, C_i), where '+' is
concatenation.

3. From C_1',...,C_n', P creates the manifest M(N) as per the {{FLIC}} specification.

4. P inserts H(D) into the root node of M(N). (This is described in the following section.)

When complete, P publishes the manifest tree M(N) and its constituent nameless object pieces.

# FLIC Support

The {{FLIC}} format already includes the metadata value OverallDataDigest. For
a given FLIC node F_i, this value corresponds to H(D_i), where D_i is the array of
application data in the nameless content objects *contained in* F_i. If F is the
root of M(N), then H(D) is the hash of complete set of application data in the manifest.
Therefore, CLEAN does not require any changes in the FLIC format.

# Use Cases

Since the data digest (i.e., H(D)) is contained in the root manifest, the privacy
of nameless content objects reduces to that of the root manifest. This has the following
benefits:

1. If access control to D is needed, P need only apply the necessary access control scheme
to the root manifest so that H(D) is not leaked. This permits the encrypted nameless
object leaves to be de-duplicated naturally in the network.
2. If D is public data that a consumer Cr wishes to retrieve privately, the root manifest
can be requested over a secure, ephemeral session between Cr and P. One way to establish
such a channel is with {{CCNxKE}}. Of course, if D is public, then any malicious consumer Adv
may follow this approach to obtain D and decrypt nameless objects, or learn what data
was requested by other consumers. However, Adv is forced to guess which name N was
requested to be successful in either attack.

In both cases, the nameless content objects that carry segments of D remain protected
without applying any type of encryption-based access control to them individually.

# Security Considerations

The CLEAN security model depends on the root manifest being protected either at rest
or, optionally, in transit. If the root is protected at rest via some access control
mechanism, then CLEAN remains secure in the MLE model. MLE security also
holds if the root is encrypted only in transit over a secure session.
