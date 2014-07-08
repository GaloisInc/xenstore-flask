(*
 * context_db.mli --- Parent-to-child security context mapping.
 *
 * Copyright (C) 2014, Galois, Inc.
 * All Rights Reserved.
 *
 * Released under the BSD3 license.  See the file "LICENSE"
 * for details.
 *
 * Written by James Bielman <jamesjb@galois.com>, 2 January 2014
 *)

type t
(** Context database type. *)

val empty : t
(** The empty context database. *)

val query_context : string -> t -> string option
(** Look up each element of a security context in the
    database, returning the complete remapped context,
    or None if any element was not able to be mapped. *)

val insert_user : string -> string -> t -> t
(** Insert or replace a user mapping in the database. *)

val query_user : string -> t -> string option
(** Look up a user mapping in the database. *)

val insert_role : string -> string -> t -> t
(** Insert or replace a role mapping in the database. *)

val query_role : string -> t -> string option
(** Look up a user mapping in the database. *)

val insert_type : string -> string -> t -> t
(** Insert or replace a type mapping in the database. *)

val query_type : string -> t -> string option
(** Look up a user mapping in the database. *)

