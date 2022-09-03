open! Core

let pseudo_pad_stream (header : Header.t) ~key =
  let base_size =
    4 (* session id *) + String.length key + 1 (* Version *) + 4 (* Sequence number *)
  in
  let pad = Iobuf.create ~len:base_size in
  let bytes = Bytes.create (base_size + Md5_lib.length) in
  Iobuf.Fill.uint32_be_trunc pad header.session_id;
  Iobuf.Fill.stringo pad key;
  Header.Version_number.write pad header.version;
  Iobuf.Fill.uint32_be_trunc pad header.sequence_number;
  Iobuf.flip_lo pad;
  Iobuf.Consume.To_bytes.blito ~src:(Iobuf.read_only pad) ~dst:bytes ();
  let initial_md5 = Md5_lib.subbytes bytes ~pos:0 ~len:base_size |> Md5_lib.to_binary in
  Sequence.unfold ~init:initial_md5 ~f:(fun md5 ->
      Bytes.From_string.blito ~src:md5 ~dst:bytes ~dst_pos:base_size ();
      let next = Md5_lib.bytes bytes |> Md5_lib.to_binary in
      Some (md5, next))
;;

let xor_char c1 c2 = Char.of_int_exn (Char.to_int c1 lxor Char.to_int c2)

let process iobuf (header : Header.t) ~key =
  let stream = pseudo_pad_stream header ~key in
  Sequence.fold_until
    stream
    ~init:0
    ~f:(fun pos pad ->
      String.iteri pad ~f:(fun i c ->
          let pos = pos + i in
          if pos < header.length
          then Iobuf.Poke.char iobuf (xor_char c (Iobuf.Peek.char iobuf ~pos)) ~pos);
      let entire_pad_processed_pos = String.length pad + pos in
      if entire_pad_processed_pos >= header.length
      then Stop ()
      else Continue entire_pad_processed_pos)
    ~finish:ignore
;;
