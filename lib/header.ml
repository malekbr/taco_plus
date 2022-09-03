open! Core
open! Async
open! Helpers

module Type = struct
  module T = struct
    type t =
      | Authentication
      | Authorization
      | Accounting
    [@@deriving sexp_of, compare, enumerate]

    let description = "packet type"

    let code = function
      | Authentication -> 0x01
      | Authorization -> 0x02
      | Accounting -> 0x03
    ;;
  end

  include T
  include Make_enum (T)
end

module Flags = struct
  module T = struct
    type t =
      { unencrypted : bool
      ; single_connection_mode : bool
      }
    [@@deriving sexp_of, compare, typed_fields]

    let mask (type a) (t : a Typed_field.t) =
      match t with
      | Unencrypted -> 0x1
      | Single_connection_mode -> 0x4
    ;;

    let all_bool (type a) (t : a Typed_field.t) : (bool, a) Type_equal.t =
      match t with
      | Unencrypted -> T
      | Single_connection_mode -> T
    ;;
  end

  include T
  include Make_flags (T)
end

module Version_number : sig
  type t = private int [@@deriving sexp_of, compare, equal]

  val parse : (t, _, _) Iobuf.Consume.t
  val write : (t, _, _) Iobuf.Fill.t
  val minor_version_0 : t
  val minor_version_1 : t
end = struct
  type t = Int.Hex.t [@@deriving sexp_of, compare]

  let equal = equal

  let parse iobuf =
    match Iobuf.Consume.uint8 iobuf with
    | (0xC0 | 0xC1) as t -> t
    | version -> parse_error_s [%message "Unknown tacacs version" (version : Int.Hex.t)]
  ;;

  let minor_version_0 = 0xC0
  let minor_version_1 = 0xC1
  let write = Iobuf.Fill.uint8_trunc
end

type t =
  { version : Version_number.t
  ; type_ : Type.t
  ; sequence_number : int
  ; flags : Flags.t
  ; session_id : int (* Needs 32 bits *)
  ; length : int (* Needs 32 bits, does not include the header *)
  }
[@@deriving sexp_of, compare]

let parse iobuf =
  let version = Version_number.parse iobuf in
  let type_ = Type.parse iobuf in
  let sequence_number = Iobuf.Consume.uint8 iobuf in
  let flags = Flags.parse iobuf in
  let session_id = Iobuf.Consume.int32_be iobuf in
  let length = Iobuf.Consume.int32_be iobuf in
  { version; type_; sequence_number; flags; session_id; length }
;;

let write iobuf { version; type_; sequence_number; flags; session_id; length } =
  Version_number.write iobuf version;
  Type.write iobuf type_;
  Iobuf.Fill.uint8_trunc iobuf sequence_number;
  Flags.write iobuf flags;
  Iobuf.Fill.uint32_be_trunc iobuf session_id;
  Iobuf.Fill.uint32_be_trunc iobuf length
;;
