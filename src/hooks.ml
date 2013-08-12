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

(** Default Path Database *)

(* This is hard-coded here for now.  Eventually it will probably become
 * a loadable module along with the Xenstore policy.
 *
 * The labels defined here must be defined in the Xen policy, or the
 * nodes will end up labeled incorrectly. *)
let ctx ty = Path_db.Value_str ("system_u:object_r:" ^ ty)
let dom    = Path_db.Value_domid

let default_path_db = Path_db.build_db
  (* local domain tree *)
  [ ("/local/domain",                             ctx "xs_local_domain_path_t")
  ; ("/local/domain/*",                           dom)
  (* device backends *)
  ; ("/local/domain/*/backend/vbd",               ctx "xs_disk_backend_path_t")
  ; ("/local/domain/*/backend/vbd/*",             dom)
  ; ("/local/domain/*/backend/vtpm",              ctx "xs_vtpm_backend_path_t")
  ; ("/local/domain/*/backend/vtpm/*",            dom)
  ; ("/local/domain/*/backend/*",                 ctx "xs_generic_backend_path_t")
  ; ("/local/domain/*/backend/*/*",               dom)
  (* device frontends *)
  ; ("/local/domain/*/device/vbd",                ctx "xs_disk_frontend_path_t")
  ; ("/local/domain/*/device/vtpm",               ctx "xs_vtpm_frontend_path_t")
  (* xenstore tool *)
  ; ("/tool/xenstored",                           ctx "xs_tool_xenstore_path_t")
  ; ("/tool/xenstored/connection/domain/*",       dom)
  ]

(** Node Labelling *)

(* Return the last element of a list. *)
let rec last xs =
  match xs with
  | []      -> raise Not_found
  | x :: [] -> x
  | x :: xs -> last xs

(* Wrapper around "context_to_sid" that returns the predefined
 * unlabeled SID if an error occurs. *)
let safe_context_to_sid label =
  try
    Sec.context_to_sid label
  with Failure _ ->
    Policy.InitialSID.xenstore_unlabeled

(* Label a newly created node based on the path database
 * and label of the (already existing) parent node. *)
let new_node_label path parent_label =
  let results = Path_db.query path default_path_db in
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
        let sid1 = safe_context_to_sid parent_label in
        let sid2 = safe_context_to_sid label in
        let sid3 = Sec.create sid1 sid2 Policy.Class.xenstore in
        Sec.sid_to_context sid3
      (* transition(getdomainsid(last(wilds)), parent_label) -> new_label *)
      | Path_db.Value_domid ->
        let domid = int_of_string (last (Path_db.(r.result_wilds))) in
        let sid1  = OS.Flask.getdomainsid domid in
        let sid2  = safe_context_to_sid parent_label in
        let sid3  = Sec.create sid1 sid2 Policy.Class.xenstore in
        Sec.sid_to_context sid3)

(* Open a connection at startup.  This is currently a no-op, but if it
 * needs to actually do something, it might need to run at a different
 * time. *)
let itf = Sec.interface_open ()

(* Perform an access check, raising an exception if it fails. *)
let do_check ssid tsid av ad =
  if not (Sec.has_perm itf ssid tsid Class.xenstore av ad)
    then raise Xenstore_server.Perms.Permission_denied
    else ()

(** Node Accesses *)

(* Create audit data for a node access. *)
let node_access_audit_data domid path extra =
  [("domid", string_of_int domid); ("path",  path)] @ extra

(* Check access from a client domain against a Xenstore node. *)
let node_access dom_id node_path node_label av ad_extra =
  let ad = node_access_audit_data dom_id node_path ad_extra in
  let dom_sid = OS.Flask.getdomainsid dom_id in
  let node_sid = safe_context_to_sid node_label in
  do_check dom_sid node_sid av ad

let flask_read dom_id node_path node_label =
  node_access dom_id node_path node_label Perm.xenstore__read []

let flask_write dom_id node_path node_label =
  node_access dom_id node_path node_label Perm.xenstore__write []

let flask_create dom_id node_path node_label =
  node_access dom_id node_path node_label Perm.xenstore__create []

let flask_delete dom_id node_path node_label =
  node_access dom_id node_path node_label Perm.xenstore__delete []

let flask_chmod dom_id node_path node_label dac_perms =
  node_access dom_id node_path node_label Perm.xenstore__chmod
              [("dac_perms", dac_perms)]

let flask_relabelfrom dom_id node_path node_label =
  node_access dom_id node_path node_label Perm.xenstore__relabelfrom []

let flask_relabelto dom_id node_path node_label =
  node_access dom_id node_path node_label Perm.xenstore__relabelto []

let flask_override dom_id node_path node_label =
  node_access dom_id node_path node_label Perm.xenstore__override []

(** Node-Node Operations *)

let flask_bind dom_id parent_path parent_label child_path child_label =
  let ad = [ ("domid", string_of_int dom_id)
           ; ("parent", parent_path); ("child", child_path) ] in
  let parent_sid = safe_context_to_sid parent_label in
  let child_sid  = safe_context_to_sid child_label in
  do_check parent_sid child_sid Perm.xenstore__bind ad

let flask_transition dom_id path old_label new_label =
  let ad = [ ("domid", string_of_int dom_id); ("path", path)
           ; ("old_label", old_label); ("new_label", new_label) ] in
  let old_sid = safe_context_to_sid old_label in
  let new_sid = safe_context_to_sid new_label in
  do_check old_sid new_sid Perm.xenstore__transition ad

(** Domain Accesses *)

let domid_access sdomid tdomid av =
  let ad = [ ("sdomid", string_of_int sdomid)
           ; ("tdomid", string_of_int tdomid)] in
  let ssid = OS.Flask.getdomainsid sdomid in
  let tsid = OS.Flask.getdomainsid tdomid in
  do_check ssid tsid av ad

let flask_introduce sdomid tdomid =
  domid_access sdomid tdomid Perm.xenstore__introduce

let flask_stat sdomid tdomid =
  domid_access sdomid tdomid Perm.xenstore__stat

let flask_release sdomid tdomid =
  domid_access sdomid tdomid Perm.xenstore__release

let flask_resume sdomid tdomid =
  domid_access sdomid tdomid Perm.xenstore__resume

let flask_chown_from sdomid tdomid =
  domid_access sdomid tdomid Perm.xenstore__chown_from

let flask_chown_to sdomid tdomid =
  domid_access sdomid tdomid Perm.xenstore__chown_to

let flask_chown_transition sdomid tdomid =
  domid_access sdomid tdomid Perm.xenstore__chown_transition

