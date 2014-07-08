(*
 * context_db.ml --- Parent-to-child security context mapping.
 *
 * Copyright (C) 2014, Galois, Inc.
 * All Rights Reserved.
 *
 * Released under the BSD3 license.  See the file "LICENSE"
 * for details.
 *
 * Written by James Bielman <jamesjb@galois.com>, 2 January 2014
 *)

(* An associative map with string keys. *)
module StringMap = Map.Make (String)

type t = {
  db_users : string StringMap.t;
  db_roles : string StringMap.t;
  db_types : string StringMap.t;
}

let empty = {
  db_users = StringMap.empty;
  db_roles = StringMap.empty;
  db_types = StringMap.empty;
}

let insert_user u1 u2 x =
  {x with db_users = StringMap.add u1 u2 x.db_users}

let insert_role r1 r2 x =
  {x with db_roles = StringMap.add r1 r2 x.db_roles}

let insert_type t1 t2 x =
  {x with db_types = StringMap.add t1 t2 x.db_types}

let maybe_find x m =
  try
    Some (StringMap.find x m)
  with
    Not_found -> None

let query_user u x = maybe_find u x.db_users
let query_role r x = maybe_find r x.db_roles
let query_type t x = maybe_find t x.db_types

let split_context s =
  match Str.split (Str.regexp_string ":") s with
  | [u; r; t] -> Some (u, r, t)
  | _         -> None

let query_context ctx db =
  match split_context ctx with
  | Some (u1, r1, t1) ->
    begin
      match (query_user u1 db, query_role r1 db, query_type t1 db) with
      | (Some u2, Some r2, Some t2) ->
        Some (u2 ^ ":" ^ r2 ^ ":" ^ t2)
      | _ -> None
    end
  | _ -> None

