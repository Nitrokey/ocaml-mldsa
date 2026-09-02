(* Emit the target-specific C/asm flags for the mldsa stubs.
   Run by dune with the *target* architecture (%{ocaml-config:architecture}),
   so it does the right thing under `dune build -x solo5`.
   Override completely with the MLDSA_ARCH_CFLAGS environment variable
   (use the value "none" for no target-specific flags at all). *)
let () =
  let arch = Sys.argv.(1) in
  let override = Sys.argv.(2) in
  let flags =
    if override = "none" then []
    else if override <> "" then String.split_on_char ' ' override |> List.filter (( <> ) "")
    else
      match arch with
      (* Assume AVX2 + BMI2 (required by the x86-64 backend; every x86-64 CPU
         since Haswell/Zen). *)
      | "amd64" -> [ "-mavx2"; "-mbmi2" ]
      (* Tune for Raspberry Pi 5 (Cortex-A76, Armv8.2-A). Deliberately no
         +sha3: the A76 lacks the EOR3 extension, so the backend uses the
         scalar/Neon Keccak variants. *)
      | "arm64" -> [ "-mcpu=cortex-a76" ]
      | _ -> []
  in
  (* one flag per line for %{read-lines:...}, and an s-expression for (:include) *)
  let oc = open_out Sys.argv.(3) in
  List.iter (fun f -> output_string oc (f ^ "\n")) flags;
  close_out oc;
  let oc = open_out Sys.argv.(4) in
  output_string oc ("(" ^ String.concat " " flags ^ ")\n");
  close_out oc
