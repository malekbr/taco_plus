open! Core

module Authentication = struct
  module Ascii = struct
    type t = { max_get_user_retries : int } [@@deriving sexp_of, compare]
  end

  module Or_disabled = struct
    type 'a t =
      | Enabled of 'a
      | Disabled
    [@@deriving sexp_of, compare, variants]

    let some_if_enabled = enabled_val

    module No_arg = struct
      type nonrec t = unit t [@@deriving sexp_of, compare]
    end
  end

  type t =
    { ascii : Ascii.t Or_disabled.t
    ; pap : Or_disabled.No_arg.t
    }
  [@@deriving sexp_of, compare]
end

type t = { authentication : Authentication.t } [@@deriving sexp_of, compare]
