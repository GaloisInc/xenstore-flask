(*
 * path_db.mli --- Xenstore path database.
 *
 * Copyright (C) 2013, Galois, Inc.
 * All Rights Reserved.
 *
 * Released under the BSD3 license.  See the file "LICENSE"
 * for details.
 *
 * Written by James Bielman <jamesjb@galois.com>, 7 August 2013
 *)

type node_value
  = Value_str of string
  | Value_domid
  | Value_none
(** Node value type, a security context or use the domain ID.

    The type 'Value_none' is for nodes that aren't actually
    in the path database but exist because they have children. *)

type t
(** Path database type. *)

val empty : t
(** The empty path database. *)

val insert : string -> node_value -> int -> t -> t
(** [insert path value metric db]

    Insert a new entry into the path database.  The 'metric'
    is used to sort queries that return multiple results due
    to wildcard matching (lower is higher priority). *)

val build_db : (string * node_value) list -> t
(** Build a database from a list of path/value tuples. *)

type result = {
  result_value : node_value;
  result_metric : int;
  result_wilds : string list;
}
(** A query result. *)

val query : string -> t -> result list
(** Query the path database, returning a list of all results
    that match.  The results are sorted by metric in ascending
    order. *)

