open! Core

module T = struct
  type 'a t =
    | Return : 'a -> 'a t
    | Bind : 'a t * ('a -> 'b t) -> 'b t
    | Map : 'a t * ('a -> 'b) -> 'b t
    | Log : string -> unit t
    | Validate_password :
        { username : string
        ; password : string
        }
        -> bool t
  [@@deriving sexp_of]

  let return x = Return x

  let bind t ~f =
    match t with
    | Return x -> f x
    | t -> Bind (t, f)
  ;;

  let map t ~f =
    match t with
    | Return x -> Return (f x)
    | t -> Map (t, f)
  ;;

  let map = `Custom map
end

include T
include Monad.Make (T)
