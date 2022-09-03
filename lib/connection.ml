open! Core
open! Async
open! Helpers

(* TODO make it IO independent and use the ipaddr type *)

let protect_bounds iobuf ~f =
  let lo_bound = Iobuf.Lo_bound.limit iobuf in
  let hi_bound = Iobuf.Hi_bound.limit iobuf in
  try f iobuf with
  | exn ->
    Iobuf.Lo_bound.restore lo_bound iobuf;
    Iobuf.Hi_bound.restore hi_bound iobuf;
    Exn.raise_without_backtrace exn
;;

let on_handler_error address (exn : exn) =
  match exn with
  | Parse_error error ->
    Log.Global.error_s
      [%message
        "Failed to parse input" (address : Socket.Address.Inet.t) (error : Sexp.t)]
  | Runtime_error error ->
    Log.Global.error_s
      [%message "Runtime error" (address : Socket.Address.Inet.t) (error : Sexp.t)]
  | exn -> Exn.reraise exn "Unexpected error"
;;

let protect_read' reader parse =
  match%map
    Reader.read_one_iobuf_at_a_time reader ~handle_chunk:(fun iobuf ->
        return
        @@
        match protect_bounds ~f:parse iobuf with
        | result -> result
        | exception (Parse_error _ as exn) -> Exn.raise_without_backtrace exn
        | exception _ -> `Continue)
  with
  | `Eof | `Eof_with_unconsumed_data _ -> parse_errorf "Got EOF while parsing packet"
  | `Stopped a -> a
;;

let protect_read reader parse = protect_read' reader (fun iobuf -> `Stop (parse iobuf))

let with_packet_content reader (header : Header.t) parse ~key =
  protect_read' reader (fun iobuf ->
      if Iobuf.length iobuf < header.length
      then `Continue
      else (
        let buffer = Iobuf.sub_shared ~len:header.length iobuf in
        Iobuf.advance iobuf header.length;
        if not header.flags.unencrypted
        then (
          match key with
          | None -> runtime_errorf "Could not find encryption key in config"
          | Some key -> Obfuscation.process buffer header ~key);
        `Stop (parse buffer)))
;;

module Flow_state = struct
  type t =
    | No_flow
    | Authentication of Authentication.Packed.t
end

let handle_packet reader (flow_state : Flow_state.t) config address ~key =
  let%bind header = protect_read reader Header.parse in
  match header.type_, flow_state with
  | Authentication, No_flow ->
    let%bind packet = with_packet_content reader header Authentication.Start.parse ~key in
    let response = Authentication.init header packet config in
    assert false
  | Authentication, Authentication (T _) ->
    let%bind packet =
      with_packet_content reader header Authentication.Continue.parse ~key
    in
    assert false
;;

let listen config ~port =
  Tcp.Server.create
    ~on_handler_error:(`Call on_handler_error)
    (Tcp.Where_to_listen.of_port port)
    (fun (`Inet (address, _port)) reader _writer ->
      let key = Config.find_key config address in
      handle_packet reader No_flow config address ~key)
;;
