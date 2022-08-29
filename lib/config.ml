open! Core

type t = { ascii_login_max_get_user_retries : int } [@@deriving sexp_of, compare]
