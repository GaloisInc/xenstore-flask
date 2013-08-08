(*
 * hooks.ml --- Xenstore security hooks.
 *
 * Copyright (C) 2013, Galois, Inc.
 * All Rights Reserved.
 *
 * Written by James Bielman <jamesjb@galois.com>, 8 August 2013
 *)

open Policy

module Sec = Security.AVC(OS.Flask)

type domid = int
type path = string
type context = string

(** Node Labelling *)

(* Return the last element of a list. *)
let rec last xs =
  match xs with
  | []      -> raise Not_found
  | x :: [] -> x
  | x :: xs -> last xs

(* Label a newly created node based on the path database
 * and label of the (already existing) parent node. *)
let new_node_label path_db path parent_label =
  let results = Path_db.query path path_db in
  match results with
  (* Not in path database, use parent's security label. *)
  | [] -> parent_label
  (* Use first result as sorted by the path DB query. *)
  | r :: _ ->
    (match Path_db.(r.result_value) with
      (* should never happen, raise an exception *)
      | Path_db.Value_none ->
        raise (Failure "new_node_label: result of Value_none")
      (* transition(parent_label, path_db_label) -> new_label *)
      | Path_db.Value_str label ->
        let sid1 = Sec.context_to_sid parent_label in
        let sid2 = Sec.context_to_sid label in
        let sid3 = Sec.create sid1 sid2 Policy.Class.xenstore in
        Sec.sid_to_context sid3
      (* transition(getdomainsid(last(wilds)), parent_label) -> new_label *)
      | Path_db.Value_domid ->
        let domid = int_of_string (last (Path_db.(r.result_wilds))) in
        let sid1  = OS.Flask.getdomainsid domid in
        let sid2  = Sec.context_to_sid parent_label in
        let sid3  = Sec.create sid1 sid2 Policy.Class.xenstore in
        Sec.sid_to_context sid3)

(** Node Accesses *)

(* Open a connection at startup.  This is currently a no-op, but if it
 * needs to actually do something, it might need to run at a different
 * time. *)
let itf = Sec.interface_open ()

(* Create audit data for a node access. *)
let node_access_audit_data domid path =
  [("domid", string_of_int domid); ("path",  path)]

(* Check access from a client domain against a Xenstore node. *)
let node_access dom_id node_path node_label av =
  let ad = node_access_audit_data dom_id node_path in
  let dom_sid = OS.Flask.getdomainsid dom_id in
  let node_sid = Sec.context_to_sid node_label in
  if not (Sec.has_perm itf dom_sid node_sid Class.xenstore av ad)
    then raise Xenstore_server.Perms.Permission_denied
    else ()

(* Read a node, its permissions, security label, or list its children. *)
let flask_read dom_id node_path node_label =
  node_access dom_id node_path node_label Perm.xenstore__read

(* Write to a node or create child nodes. *)
let flask_write dom_id node_path node_label =
  node_access dom_id node_path node_label Perm.xenstore__write

