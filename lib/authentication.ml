open! Core
open! Helpers

module Action = struct
  module T = struct
    type t =
      | Login
      | Chpass
      | Sendauth
    [@@deriving sexp_of, compare, enumerate]

    let description = "authentication action"

    let code = function
      | Login -> 0x01
      | Chpass -> 0x02
      | Sendauth -> 0x04
    ;;
  end

  include T
  include Make_enum (T)
end

module Type = struct
  module T = struct
    type t =
      | Ascii
      | Pap
      | Chap
      | Mschap
      | Mschap_v2
    [@@deriving sexp_of, compare, enumerate]

    let description = "authentication type"

    let code = function
      | Ascii -> 0x01
      | Pap -> 0x02
      | Chap -> 0x03
      | Mschap -> 0x05
      | Mschap_v2 -> 0x06
    ;;
  end

  include T
  include Make_enum (T)
end

module Service = struct
  module T = struct
    type t =
      | None
      | Login
      | Enable
      | PPP
      | PT
      | Rcmd
      | X25
      | NASI
      | Fwproxy
    [@@deriving sexp_of, equal, compare, enumerate]

    let description = "authentication service"

    let code = function
      | None -> 0x00
      | Login -> 0x01
      | Enable -> 0x02
      | PPP -> 0x03
      | PT -> 0x05
      | Rcmd -> 0x06
      | X25 -> 0x07
      | NASI -> 0x08
      | Fwproxy -> 0x09
    ;;
  end

  include T
  include Make_enum (T)
end

module Status = struct
  module T = struct
    type t =
      | Pass
      | Fail
      | Get_data
      | Get_user
      | Get_pass
      | Restart
      | Error
      | Follow
    [@@deriving sexp_of, compare, enumerate]

    let description = "authentication service"

    let code = function
      | Pass -> 0x01
      | Fail -> 0x02
      | Get_data -> 0x03
      | Get_user -> 0x04
      | Get_pass -> 0x05
      | Restart -> 0x06
      | Error -> 0x07
      | Follow -> 0x21
    ;;
  end

  include T
  include Make_enum (T)
end

module Reply_flags = struct
  module T = struct
    type t = { no_echo : bool } [@@deriving sexp_of, compare, typed_fields]

    let mask (type a) (t : a Typed_field.t) =
      match t with
      | No_echo -> 0x1
    ;;

    let all_bool (type a) (t : a Typed_field.t) : (bool, a) Type_equal.t =
      match t with
      | No_echo -> T
    ;;
  end

  include T
  include Helpers.Make_flags (T)
end

module Continue_flags = struct
  module T = struct
    type t = { abort : bool } [@@deriving sexp_of, compare, typed_fields]

    let mask (type a) (t : a Typed_field.t) =
      match t with
      | Abort -> 0x1
    ;;

    let all_bool (type a) (t : a Typed_field.t) : (bool, a) Type_equal.t =
      match t with
      | Abort -> T
    ;;
  end

  include T
  include Helpers.Make_flags (T)
end

module Start = struct
  type t =
    { action : Action.t
    ; privilege_level : int
    ; type_ : Type.t
    ; service : Service.t
    ; user : string option (* TODO make this a non empty string type *)
    ; port : string
    ; remote_address : string option (* TODO make this a non empty string type *)
    ; data : string
    }
  [@@deriving sexp_of, compare]

  let parse iobuf =
    let action = Action.parse iobuf in
    let privilege_level = Iobuf.Consume.uint8 iobuf in
    let type_ = Type.parse iobuf in
    let service = Service.parse iobuf in
    let user_length = Iobuf.Consume.uint8 iobuf in
    let port_length = Iobuf.Consume.uint8 iobuf in
    let remote_address_length = Iobuf.Consume.uint8 iobuf in
    let data_length = Iobuf.Consume.uint8 iobuf in
    let user =
      if user_length = 0
      then None
      else Some (Iobuf.Consume.stringo ~len:user_length iobuf)
    in
    let port = Iobuf.Consume.stringo ~len:port_length iobuf in
    let remote_address =
      if remote_address_length = 0
      then None
      else Some (Iobuf.Consume.stringo ~len:remote_address_length iobuf)
    in
    let data = Iobuf.Consume.stringo ~len:data_length iobuf in
    { action; privilege_level; type_; service; user; port; remote_address; data }
  ;;

  let write
      iobuf
      { action; privilege_level; type_; service; user; port; remote_address; data }
    =
    Action.write iobuf action;
    Iobuf.Fill.uint8_trunc iobuf privilege_level;
    Type.write iobuf type_;
    Service.write iobuf service;
    Iobuf.Fill.uint8_trunc iobuf (Option.value_map ~f:String.length user ~default:0);
    Iobuf.Fill.uint8_trunc iobuf (String.length port);
    Iobuf.Fill.uint8_trunc
      iobuf
      (Option.value_map ~f:String.length remote_address ~default:0);
    Iobuf.Fill.uint8_trunc iobuf (String.length data);
    Option.iter ~f:(Iobuf.Fill.stringo iobuf) user;
    Iobuf.Fill.stringo iobuf port;
    Option.iter ~f:(Iobuf.Fill.stringo iobuf) remote_address;
    Iobuf.Fill.stringo iobuf data
  ;;
end

module Reply = struct
  type t =
    { status : Status.t
    ; flags : Reply_flags.t
    ; server_message : string option
    ; data : string
    }
  [@@deriving sexp_of, compare]

  let parse iobuf =
    let status = Status.parse iobuf in
    let flags = Reply_flags.parse iobuf in
    let server_message_length = Iobuf.Consume.uint8 iobuf in
    let data_length = Iobuf.Consume.uint8 iobuf in
    let server_message =
      if server_message_length = 0
      then None
      else Some (Iobuf.Consume.stringo ~len:server_message_length iobuf)
    in
    let data = Iobuf.Consume.stringo ~len:data_length iobuf in
    { status; flags; server_message; data }
  ;;

  let write iobuf { status; flags; server_message; data } =
    Status.write iobuf status;
    Reply_flags.write iobuf flags;
    Iobuf.Fill.uint8_trunc
      iobuf
      (Option.value_map ~f:String.length server_message ~default:0);
    Iobuf.Fill.uint8_trunc iobuf (String.length data);
    Option.iter ~f:(Iobuf.Fill.stringo iobuf) server_message;
    Iobuf.Fill.stringo iobuf data
  ;;

  let get_user =
    { status = Get_user; flags = { no_echo = false }; server_message = None; data = "" }
  ;;

  let get_password =
    { status = Get_pass; flags = { no_echo = false }; server_message = None; data = "" }
  ;;

  let fail ?server_message ?(data = "") () =
    { status = Fail; flags = { no_echo = false }; server_message; data }
  ;;

  let error ?server_message ?(data = "") () =
    { status = Error; flags = { no_echo = false }; server_message; data }
  ;;

  let pass ?server_message ?(data = "") () =
    { status = Pass; flags = { no_echo = false }; server_message; data }
  ;;
end

module Continue = struct
  type t =
    { flags : Continue_flags.t
    ; user : string option
    ; data : string
    }
  [@@deriving sexp_of, compare]

  let parse iobuf =
    let user_length = Iobuf.Consume.uint8 iobuf in
    let data_length = Iobuf.Consume.uint8 iobuf in
    let flags = Continue_flags.parse iobuf in
    let user =
      if user_length = 0
      then None
      else Some (Iobuf.Consume.stringo ~len:user_length iobuf)
    in
    let data = Iobuf.Consume.stringo ~len:data_length iobuf in
    { user; data; flags }
  ;;

  let write iobuf { user; data; flags } =
    Iobuf.Fill.uint8_trunc iobuf (Option.value_map ~f:String.length user ~default:0);
    Iobuf.Fill.uint8_trunc iobuf (String.length data);
    Continue_flags.write iobuf flags;
    Option.iter ~f:(Iobuf.Fill.stringo iobuf) user;
    Iobuf.Fill.stringo iobuf data
  ;;
end

module Flow_response = struct
  type 'state t =
    { state : [ `State of 'state | `Finished ]
    ; reply : Reply.t
    }
  [@@deriving sexp_of, compare]

  let make_state state reply = { state = `State state; reply }
  let final reply = { state = `Finished; reply }
end

module type Flow_state_machine = sig
  type t [@@deriving sexp_of, compare]

  val init : Header.t -> Start.t -> Config.t -> t Flow_response.t State_action.t option
  val continue : t -> Continue.t -> t Flow_response.t State_action.t
end

module Ascii_login : Flow_state_machine = struct
  open! State_action.Let_syntax

  type t =
    | Request_user of { remaining_retries : int }
    | Request_password of { username : string }
  [@@deriving sexp_of, compare]

  let init (header : Header.t) (start : Start.t) (config : Config.t) =
    match start.action, start.type_ with
    | Login, Ascii
      when Header.Version_number.(equal minor_version_0) header.version
           && not (Service.equal start.service Enable) ->
      Option.return
      @@ return
      @@
      (match start.user with
      | None ->
        Flow_response.make_state
          (Request_user { remaining_retries = config.ascii_login_max_get_user_retries })
          Reply.get_user
      | Some username ->
        Flow_response.make_state (Request_password { username }) Reply.get_password)
    | _ -> None
  ;;

  let continue t (continue : Continue.t) =
    match t with
    | Request_user { remaining_retries } ->
      let remaining_retries = remaining_retries - 1 in
      (match continue.user with
      | None ->
        if remaining_retries <= 0
        then (
          let%map () = Log "Ascii auth failed, get_user ran out of attempts" in
          Reply.fail () |> Flow_response.final)
        else
          Flow_response.make_state (Request_user { remaining_retries }) Reply.get_user
          |> return
      | Some username ->
        Flow_response.make_state (Request_password { username }) Reply.get_password
        |> return)
    | Request_password { username } ->
      (match continue.user with
      | None -> Reply.error () |> Flow_response.final |> return
      | Some password ->
        if%map Validate_password { username; password }
        then Reply.pass () |> Flow_response.final
        else Reply.fail () |> Flow_response.final)
  ;;
end
