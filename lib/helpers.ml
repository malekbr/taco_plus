open! Core

exception Parse_error of Sexp.t
exception Runtime_error of Sexp.t

let parse_error_s sexp = raise (Parse_error sexp)
let parse_errorf format = Printf.ksprintf (fun s -> parse_error_s (Atom s)) format
let runtime_error_s sexp = raise (Parse_error sexp)
let runtime_errorf format = Printf.ksprintf (fun s -> parse_error_s (Atom s)) format

module Make_enum (M : sig
  type t [@@deriving enumerate]

  val description : string
  val code : t -> int
end) =
struct
  let reverse_lookup =
    let max = List.map M.all ~f:M.code |> List.max_elt ~compare |> Option.value_exn in
    let array = Option_array.create ~len:(max + 1) in
    List.iter M.all ~f:(fun t -> Option_array.set_some array (M.code t) t);
    fun int ->
      match Option_array.get array int with
      | Some t -> t
      | None | (exception _) -> parse_errorf "Unknown %s code %X" M.description int
  ;;

  let parse iobuf = Iobuf.Consume.int8 iobuf |> reverse_lookup
  let write iobuf t = Iobuf.Fill.int8_trunc iobuf (M.code t)
end

module Make_flags (M : sig
  type t

  module Typed_field : Typed_fields_lib.S with type derived_on = t

  val mask : 'a Typed_field.t -> int
  val all_bool : 'a Typed_field.t -> (bool, 'a) Type_equal.t
end) =
struct
  let decode flag =
    M.Typed_field.create
      { f = (fun t -> Type_equal.conv (M.all_bool t) (M.mask t land flag > 0)) }
  ;;

  let encode t =
    List.fold M.Typed_field.Packed.all ~init:0 ~f:(fun mask { f = T field } ->
        if M.Typed_field.get field t
           |> Type_equal.conv (Type_equal.sym (M.all_bool field))
        then mask lor M.mask field
        else mask)
  ;;

  let parse iobuf =
    let flags = Iobuf.Consume.uint8 iobuf in
    decode flags
  ;;

  let write iobuf t = encode t |> Iobuf.Fill.uint8_trunc iobuf
end
