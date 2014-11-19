(*
 * Copyright (c) 2013 David Sheets <sheets@alum.mit.edu>
 * Copyright (c) 2014 Peter Zotov <whitequark@whitequark.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

(** A binding to {{: https://github.com/jedisct1/libsodium } libsodium}
    which wraps {{: http://nacl.cr.yp.to/ } NaCl} *)

(** Raised when message authentication fails. *)
exception Verification_failure

(** Raised when attempting to deserialize a malformed key or nonce. *)
exception Size_mismatch of string

(** Phantom type indicating that the key is public. *)
type public

(** Phantom type indicating that the key is secret. *)
type secret

(** Phantom type indicating that the key is composed of a secret key and
    a public key. Such a key must be treated as a secret key. *)
type channel

type bigbytes =
  (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

module Random : sig
  val stir : unit -> unit

  module type S = sig
    type storage

    val generate_into : storage -> unit
    val generate : int -> storage
  end

  module Bytes : S with type storage = Bytes.t
  module Bigbytes : S with type storage = bigbytes
end

module Box : sig
  type 'a key
  type secret_key = secret key
  type public_key = public key
  type channel_key = channel key
  type keypair = secret key * public key
  type nonce

  (** Primitive used by this implementation.
      Currently ["curve25519xsalsa20poly1305"]. *)
  val primitive           : string

  (** Size of public keys, in bytes. *)
  val public_key_size     : int

  (** Size of secret keys, in bytes. *)
  val secret_key_size     : int

  (** Size of channel keys, in bytes. *)
  val channel_key_size    : int

  (** Size of nonces, in bytes. *)
  val nonce_size          : int

  (** [random_keypair ()] generates a random key pair. *)
  val random_keypair      : unit -> keypair

  (** [random_nonce ()] generates a random nonce. *)
  val random_nonce        : unit -> nonce

  (** [nonce_of_bytes b] creates a nonce out of bytes [b].
      If [b] is not [nonce_size] byte long, [Size_mismatch] is raised. *)
  val nonce_of_bytes      : Bytes.t -> nonce

  (** [increment_nonce ?step n] interprets nonce [n] as a big-endian
      number and returns the sum of [n] and [step] with wrap-around.
      The default [step] is 1. *)
  val increment_nonce     : ?step:int -> nonce -> nonce

  (** [wipe_key k] overwrites [k] with zeroes. *)
  val wipe_key            : 'a key -> unit

  (** [precompute sk pk] precomputes the channel key for the secret key [sk]
      and the public key [pk], which can be used to speed up processing
      of any number of messages. *)
  val precompute          : secret key -> public key -> channel key

  (** [equal_public_keys a b] checks [a] and [b] for equality in constant
      time. *)
  val equal_public_keys   : public key -> public key -> bool

  (** [equal_secret_keys a b] checks [a] and [b] for equality in constant
      time. *)
  val equal_secret_keys   : secret key -> secret key -> bool

  (** [equal_channel_keys a b] checks [a] and [b] for equality in constant
      time. *)
  val equal_channel_keys  : channel key -> channel key -> bool

  (** [compare_public_keys a b] compares [a] and [b]. *)
  val compare_public_keys : public key -> public key -> int

  module type S = sig
    type storage

    (** [of_public_key k] converts [k] to type [storage]. The result
        is [public_key_size] bytes long. *)
    val of_public_key   : public key -> storage

    (** [to_public_key s] converts [s] to a public key.
        If [s] is not [public_key_size] long, [Size_mismatch] is raised. *)
    val to_public_key   : storage -> public key

    (** [of_secret_key k] converts [k] to type [storage]. The result
        is [secret_key_size] bytes long. *)
    val of_secret_key   : secret key -> storage

    (** [to_secret_key s] converts [s] to a secret key.
        If [s] is not [secret_key_size] long, [Size_mismatch] is raised. *)
    val to_secret_key   : storage -> secret key

    (** [of_channel_key k] converts [k] to type [storage]. The result
        is [channel_key_size] bytes long. *)
    val of_channel_key  : channel key -> storage

    (** [to_channel_key s] converts [s] to a channel key.
        If [s] is not [channel_key_size] long, [Size_mismatch] is raised. *)
    val to_channel_key  : storage -> channel key

    (** [of_nonce n] converts [n] to type [storage]. The result
        is [nonce_size] bytes long. *)
    val of_nonce        : nonce -> storage

    (** [to_nonce s] converts [s] to a nonce.
        If [s] is not [nonce_size] long, [Size_mismatch] is raised. *)
    val to_nonce        : storage -> nonce

    (** [box sk pk m n] encrypts and authenticates a message [m] using
        the sender's secret key [sk], the receiver's public key [pk], and
        a nonce [n]. *)
    val box             : secret key -> public key -> storage -> nonce -> storage

    (** [box_open sk pk c n] verifies and decrypts a ciphertext [c] using
        the receiver's secret key [sk], the sender's public key [pk], and
        a nonce [n].
        If authenticity of message cannot be verified, [Verification_failure]
        is raised. *)
    val box_open        : secret key -> public key -> storage -> nonce -> storage

    (** [fast_box ck m n] encrypts and authenticates a message [m] using
        the channel key [ck] precomputed from sender's secret key
        and the receiver's public key, and a nonce [n]. *)
    val fast_box        : channel key -> storage -> nonce -> storage

    (** [fast_box_open ck c n] verifies and decrypts a ciphertext [c] using
        the channel key [ck] precomputed from receiver's secret key
        and the sender's public key, and a nonce [n].
        If authenticity of message cannot be verified, [Verification_failure]
        is raised. *)
    val fast_box_open   : channel key -> storage -> nonce -> storage
  end

  module Bytes : S with type storage = Bytes.t
  module Bigbytes : S with type storage = bigbytes
end

module Scalar_mult : sig
  type group_elt
  type integer

  (** Primitive used by this implementation. Currently ["curve25519"]. *)
  val primitive       : string

  (** Size of group elements, in bytes. *)
  val group_elt_size  : int

  (** Size of integers, in bytes. *)
  val integer_size    : int

  (** [equal_group_elt a b] checks [a] and [b] for equality in constant time. *)
  val equal_group_elt : group_elt -> group_elt -> bool

  (** [equal_integer a b] checks [a] and [b] for equality in constant time. *)
  val equal_integer   : integer -> integer -> bool

  (** [mult n p] multiplies a group element [p] by an integer [n]. *)
  val mult            : integer -> group_elt -> group_elt

  (** [base n] computes the scalar product of a standard group
      element and an integer [n]. *)
  val base            : integer -> group_elt

  module type S = sig
    type storage

    (** [of_group_elt ge] converts [ge] to type [storage]. The result
        is [group_elt_size] bytes long. *)
    val of_group_elt  : group_elt -> storage

    (** [to_group_elt s] converts [s] to a group_elt.
        If [s] is not [group_elt_size] long, [Invalid_argument] is raised. *)
    val to_group_elt  : storage -> group_elt

    (** [of_integer i] converts [i] to type [storage]. The result
        is [integer_size] bytes long. *)
    val of_integer    : integer -> storage

    (** [to_integer s] converts [s] to a integer.
        If [s] is not [integer_size] long, [Invalid_argument] is raised. *)
    val to_integer    : storage -> integer
  end

  module Bytes : S with type storage = Bytes.t
  module Bigbytes : S with type storage = bigbytes
end

module Sign : sig
  type 'a key
  type secret_key = secret key
  type public_key = public key
  type keypair = secret key * public key
  type signature

  (** Primitive used by this implementation. Currently ["ed25519"]. *)
  val primitive           : string

  (** Size of public keys, in bytes. *)
  val public_key_size     : int

  (** Size of secret keys, in bytes. *)
  val secret_key_size     : int

  (** Size of signatures, in bytes. *)
  val signature_size      : int

  (** [random_keypair ()] generates a random key pair. *)
  val random_keypair      : unit -> keypair

  (** [wipe_key k] overwrites [k] with zeroes. *)
  val wipe_key            : 'a key -> unit

  (** [equal_public_keys a b] checks [a] and [b] for equality in constant
      time. *)
  val equal_public_keys   : public key -> public key -> bool

  (** [equal_secret_keys a b] checks [a] and [b] for equality in constant
      time. *)
  val equal_secret_keys   : secret key -> secret key -> bool

  (** [compare_public_keys a b] compares [a] and [b]. *)
  val compare_public_keys : public key -> public key -> int

  module type S = sig
    type storage

    (** [of_public_key k] converts [k] to type [storage]. The result
        is [public_key_size] bytes long. *)
    val of_public_key   : public key -> storage

    (** [to_public_key s] converts [s] to a public key.
        If [s] is not [public_key_size] long, [Size_mismatch] is raised. *)
    val to_public_key   : storage -> public key

    (** [of_secret_key k] converts [k] to type [storage]. The result
        is [secret_key_size] bytes long. *)
    val of_secret_key   : secret key -> storage

    (** [to_secret_key s] converts [s] to a secret key.
        If [s] is not [secret_key_size] long, [Size_mismatch] is raised. *)
    val to_secret_key   : storage -> secret key

    (** [of_signature a] converts [a] to type [storage]. The result
        is [signature_size] bytes long. *)
    val of_signature    : signature -> storage

    (** [to_signature s] converts [s] to a signature.
        If [s] is not [signature_size] long, [Size_mismatch] is raised. *)
    val to_signature    : storage -> signature

    (** [sign sk m] signs a message [m] using the signer's secret key [sk],
        and returns the resulting signed message. *)
    val sign            : secret key -> storage -> storage

    (** [sign_open pk sm] verifies the signature in [sm] using the signer's
        public key [pk], and returns the message.
        If authenticity of message cannot be verified, [Verification_failure]
        is raised. *)
    val sign_open       : public key -> storage -> storage

    (** [sign_detached sk m] signs a message [m] using the signer's secret
        key [sk], and returns the signature. *)
    val sign_detached   : secret key -> storage -> signature

    (** [verify pk s m] checks that [s] is a correct signature of a message
        [m] under the public key [pk]. If it is not, [Verification_failed]
        is raised. *)
    val verify          : public key -> signature -> storage -> unit
  end

  module Bytes : S with type storage = Bytes.t
  module Bigbytes : S with type storage = bigbytes
end

module Secret_box : sig
  type 'a key
  type secret_key = secret key
  type nonce

  (** Primitive used by this implementation. Currently ["xsalsa20poly1305"]. *)
  val primitive       : string

  (** Size of keys, in bytes. *)
  val key_size        : int

  (** Size of nonces, in bytes. *)
  val nonce_size      : int

  (** [random_key ()] generates a random secret key . *)
  val random_key      : unit -> secret key

  (** [random_nonce ()] generates a random nonce. *)
  val random_nonce    : unit -> nonce

  (** [nonce_of_bytes b] creates a nonce out of bytes [b].
      If [b] is not [nonce_size] byte long, [Size_mismatch] is raised. *)
  val nonce_of_bytes  : Bytes.t -> nonce

  (** [increment_nonce ?step n] interprets nonce [n] as a big-endian
      number and returns the sum of [n] and [step] with wrap-around.
      The default [step] is 1. *)
  val increment_nonce : ?step:int -> nonce -> nonce

  (** [wipe_key k] overwrites [k] with zeroes. *)
  val wipe_key        : secret key -> unit

  (** [equal_keys a b] checks [a] and [b] for equality in constant time. *)
  val equal_keys      : secret key -> secret key -> bool

  module type S = sig
    type storage

    (** [of_key k] converts [k] to type [storage]. The result
        is [key_size] bytes long. *)
    val of_key          : secret key -> storage

    (** [to_key s] converts [s] to a secret key.
        If [s] is not [key_size] long, [Size_mismatch] is raised. *)
    val to_key          : storage -> secret key

    (** [of_nonce n] converts [n] to type [storage]. The result
        is [nonce_size] bytes long. *)
    val of_nonce        : nonce -> storage

    (** [to_nonce s] converts [s] to a nonce.
        If [s] is not [nonce_size] long, [Size_mismatch] is raised. *)
    val to_nonce        : storage -> nonce

    (** [secret_box k m n] encrypts and authenticates a message [m] using
        a secret key [k] and a nonce [n], and returns the resulting
        ciphertext. *)
    val secret_box      : secret key -> storage -> nonce -> storage

    (** [secret_box_open k c n] verifies and decrypts a ciphertext [c] using
        a secret key [k] and a nonce [n], and returns the resulting plaintext
        [m]. If authenticity of message cannot be verified,
        [Verification_failure] is raised. *)
    val secret_box_open : secret key -> storage -> nonce -> storage
  end

  module Bytes : S with type storage = Bytes.t
  module Bigbytes : S with type storage = bigbytes
end

module Stream : sig
  type 'a key
  type secret_key = secret key
  type nonce

  (** Primitive used by this implementation. Currently ["xsalsa20"]. *)
  val primitive       : string

  (** Size of keys, in bytes. *)
  val key_size        : int

  (** Size of nonces, in bytes. *)
  val nonce_size      : int

  (** [random_key ()] generates a random secret key . *)
  val random_key      : unit -> secret key

  (** [random_nonce ()] generates a random nonce. *)
  val random_nonce    : unit -> nonce

  (** [nonce_of_bytes b] creates a nonce out of bytes [b].
      If [b] is not [nonce_size] byte long, [Size_mismatch] is raised. *)
  val nonce_of_bytes  : Bytes.t -> nonce

  (** [increment_nonce ?step n] interprets nonce [n] as a big-endian
      number and returns the sum of [n] and [step] with wrap-around.
      The default [step] is 1. *)
  val increment_nonce : ?step:int -> nonce -> nonce

  (** [wipe_key k] overwrites [k] with zeroes. *)
  val wipe_key        : secret key -> unit

  (** [equal_keys a b] checks [a] and [b] for equality in constant time. *)
  val equal_keys      : secret key -> secret key -> bool

  module type S = sig
    type storage

    (** [of_key k] converts [k] to type [storage]. The result
        is [key_size] bytes long. *)
    val of_key          : secret key -> storage

    (** [to_key s] converts [s] to a secret key.
        If [s] is not [key_size] long, [Size_mismatch] is raised. *)
    val to_key          : storage -> secret key

    (** [of_nonce n] converts [n] to type [storage]. The result
        is [nonce_size] bytes long. *)
    val of_nonce        : nonce -> storage

    (** [to_nonce s] converts [s] to a nonce.
        If [s] is not [nonce_size] long, [Size_mismatch] is raised. *)
    val to_nonce        : storage -> nonce

    (** [stream k len n] produces a [len]-byte stream [c] as a function of
        a secret key [k] and a nonce [n]. *)
    val stream          : secret key -> int -> nonce -> storage

    (** [stream_xor k m n] encrypts or decrypts a message [m] using
        a secret key [k] and a nonce [n]. *)
    val stream_xor      : secret key -> storage -> nonce -> storage
  end

  module Bytes : S with type storage = Bytes.t
  module Bigbytes : S with type storage = bigbytes
end

module Auth : sig
  type 'a key
  type secret_key = secret key
  type auth

  (** Primitive used by this implementation. Currently ["hmacsha512256"]. *)
  val primitive   : string

  (** Size of keys, in bytes. *)
  val key_size    : int

  (** Size of authenticators, in bytes. *)
  val auth_size   : int

  (** [random_key ()] generates a random secret key . *)
  val random_key  : unit -> secret key

  (** [wipe_key k] overwrites [k] with zeroes. *)
  val wipe_key    : secret key -> unit

  (** [equal_keys a b] checks [a] and [b] for equality in constant time. *)
  val equal_keys  : secret key -> secret key -> bool

  module type S = sig
    type storage

    (** [of_key k] converts [k] to type [storage]. The result
        is [key_size] bytes long. *)
    val of_key  : secret key -> storage

    (** [to_key s] converts [s] to a secret key.
        If [s] is not [key_size] long, [Size_mismatch] is raised. *)
    val to_key  : storage -> secret key

    (** [of_auth a] converts [a] to type [storage]. The result
        is [auth_size] bytes long. *)
    val of_auth : auth -> storage

    (** [to_auth s] converts [s] to an authenticator.
        If [s] is not [auth_size] long, [Size_mismatch] is raised. *)
    val to_auth : storage -> auth

    (** [auth k m] authenticates a message [m] using a secret key [k],
        and returns an authenticator [a].  *)
    val auth    : secret key -> storage -> auth

    (** [verify k a m] checks that [a] is a correct authenticator
        of a message [m] under the secret key [k]. If it is not,
        [Verification_failed] is raised. *)
    val verify  : secret key -> auth -> storage -> unit
  end

  module Bytes : S with type storage = Bytes.t
  module Bigbytes : S with type storage = bigbytes
end

module One_time_auth : sig
  include module type of Auth

  (** Primitive used by this implementation. Currently ["poly1305"]. *)
  val primitive   : string
end

module Hash : sig
  type hash

  (** Primitive used by this implementation. Currently ["sha512"]. *)
  val primitive : string

  (** Size of hashes, in bytes. *)
  val size      : int

  (** [equal a b] checks [a] and [b] for equality in constant time. *)
  val equal     : hash -> hash -> bool

  module type S = sig
    type storage

    (** [of_hash h] converts [h] to type [storage]. The result
        is [size] bytes long. *)
    val of_hash : hash -> storage

    (** [to_hash s] converts [s] to a hash.
        If [s] is not [size] long, [Invalid_argument] is raised. *)
    val to_hash : storage -> hash

    (** [digest m] computes a hash for message [m]. *)
    val digest  : storage -> hash
  end

  module Bytes : S with type storage = Bytes.t
  module Bigbytes : S with type storage = bigbytes
end
