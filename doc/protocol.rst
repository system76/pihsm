Protocol
========


Signed Messages
---------------

All signed messages have a common 96-byte prefix, followed by zero or more bytes
of message payload to be signed::

    +------------+------------+------------+
    | Signature  | Public Key | Message    |
    | (64 bytes) | (32 bytes) | (variable) |
    +------------+------------+------------+

The first 64 bytes contains the Ed25519 signature, which signs all of the
remaining bytes in the message (the Public Key plus the Message are signed).

The next 32 bytes contains the Ed25119 public key corresponding to private key
used to make the signature.


Signature Chaining
------------------

PiHSM cryptographically ties a new signatures to the previous signature in order
to create a verifiable log about use of the particular private key.  This
chain allows the external chain to be verified as matching the latest signature
displayed on the 20x4 LCD.

All signed messages used in the protocol (aside from the genesis message,
explained below) have a common 160-byte prefix::

    +------------+------------+--------------------+------------+
    | Signature  | Public Key | Previous Signature | Message    |
    | (64 bytes) | (32 bytes) | (64 bytes)         | (variable) |
    +------------+------------+--------------------+------------+


Genesis Signature
-----------------

When the signing server starts, it generates it's private key and then signs
it's public key using it's private key::

    +-------------------+------------+
    | Genesis Signature | Public Key |
    | (64 bytes)        | (32 bytes) |
    +-------------------+------------+

This signature is the genesis signature, which will be used in the Previous
Signature field for the first signature made::

    +------------+------------+-------------------+------------+
    | Signature  | Public Key | Genesis Signature | Message    |
    | (64 bytes) | (32 bytes) | (64 bytes)        | (variable) |
    +------------+------------+-------------------+------------+


Counter & Timestamp
-------------------

The complete signed message format incorporates two addition fields: a counter
and a timestamp::

    +------------+------------+--------------------+-----------+-----------+------------+
    | Signature  | Public Key | Previous Signature | Counter   | Timestamp | Message    |
    | (64 bytes) | (32 bytes) | (64 bytes)         | (8 bytes) | (8 bytes) | (variable) |
    +------------+------------+--------------------+-----------+-----------+------------+

The *Counter* is and 64-bit unsigned integer (in little endian format). The counter
is initialized at ``0`` and is incremented *before* a signature is made.  So
the first signature will have a counter value of ``1``.  A counter value of
``0`` is not valid in the protocol (it is used to detect a counter overflow).

The *Timestamp* is likewise a 64-bit unsigned integer (in little endian format).
This field contains a Unix timestamp at which the signature was made.

All signed messages sent over the serial interface have this common 176-byte
structure.


Signing Request
---------------

To request a signature from the PiHSM server, the client must first construct
a signing request.

The signing request has the 48-byte SHA-384 digest of the manifest file being
signed::

    +------------+------------+--------------------+-----------+-----------+------------+
    | Signature  | Public Key | Previous Signature | Counter   | Timestamp | SHA-384    |
    | (64 bytes) | (32 bytes) | (64 bytes)         | (8 bytes) | (8 bytes) | (48 bytes) |
    +------------+------------+--------------------+-----------+-----------+------------+

This exact 224-byte fixed-length message is sent over the serial interface to
the signing server.


Signing Response
----------------

Upon receiving a valid signing request over the serial bus, the PiHSM server
signs the entire Signing Request.

This is the exact 400-byte fixed-length message returned::

    +------------+------------+--------------------+-----------+-----------+-------------------+
    | Signature  | Public Key | Previous Signature | Counter   | Timestamp | Signing Request   |
    | (64 bytes) | (32 bytes) | (64 bytes)         | (8 bytes) | (8 bytes) | (224 bytes)       |
    +------------+------------+--------------------+-----------+-----------+-------------------+


Wire Format
-----------

A PiHSM client (likely a build server) can only communicate with the PiHSM
server when it is physically connected using TTL serial communication.  Although
the PiHSM signing server is not truly "offline" in the sense of being
air-gapped, the fact that you can only communicate with it over TTL serial
dramatically reduces the attack surface.  Which is not to say that we have
unrealistic expectations in terms PiHSM being resistant to attack... it's always
prudent to assume there is an exploitable flaw lingering in there somewhere.

The serial protocol is as simple as possible.  This is only one interaction
possible: the client sends a 224-byte Signing Request and then the server
returns a 400-byte Signing Response.

This::

    +----------+----------------------------------------------------+----------+
    |          |                                                    |          |
    |          |  Signing Request (224 bytes) ------------------->  |          |
    |  Client  |                                                    |  Server  |
    |          |  <------------------ Signing Response (400 bytes)  |          |
    |          |                                                    |          |
    +----------+----------------------------------------------------+----------+

