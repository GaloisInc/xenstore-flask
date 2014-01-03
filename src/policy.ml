(*
 * policy.ml --- Security policy objects.
 *
 * Copyright (C) 2013, Galois, Inc.
 * All Rights Reserved.
 *
 * Written by James Bielman <jamesjb@galois.com>, 26 July 2013
 *)

open Printf

type audit_data = (string * string) list

let audit_data_to_string d =
  let go s (k, v) = s ^ sprintf " %s=%s" k v in
  String.trim (List.fold_left go "" d)

include Flask_gen
