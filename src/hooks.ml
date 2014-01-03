(*
 * hooks.ml --- Xenstore security hooks.
 *
 * Copyright (C) 2013, Galois, Inc.
 * All Rights Reserved.
 *
 * Written by James Bielman <jamesjb@galois.com>, 8 August 2013
 *)

open Policy

(* Use the built-in Xenstore security server for access control. *)
module Sec = Security.AVC(Sec_server)

type domid = int
type path = string
type context = string

let flask_clear_avc_cache () =
  Sec.avc_clear_cache ()

(** Path and Context Databases *)

let g_path_db      = ref Path_db.empty
let set_path_db db = g_path_db := db

let g_context_db      = ref Context_db.empty
let set_context_db db = g_context_db := db

(** Node Labelling *)

(* Return the last element of a list. *)
let rec last xs =
  match xs with
  | []      -> raise Not_found
  | x :: [] -> x
  | x :: xs -> last xs

(* Look up a domain SID in the hypervisor policy, then translate
 * that security context to the Xenstore policy via the context DB.
 * Returns the unlabeled context if any steps fail. *)
let safe_getdomainsid domid =
  try
    let xsm_sid = OS.Flask.getdomainsid domid in
    let xsm_ctx = OS.Flask.sid_to_context xsm_sid in
    match Context_db.query_context xsm_ctx !g_context_db with
    | Some xs_ctx -> Sec.context_to_sid xs_ctx
    | None        -> Policy.InitialSID.unlabeled
  with Failure _ ->
    Policy.InitialSID.unlabeled

(* Wrapper around "context_to_sid" that returns the predefined
 * Xenstore unlabeled SID if an error occurs. *)
let safe_context_to_sid label =
  try
    Sec.context_to_sid label
  with Failure _ ->
    Policy.InitialSID.unlabeled

(* Label a newly created node based on the path database
 * and label of the (already existing) parent node. *)
let new_node_label path parent_label =
  let results = Path_db.query path !g_path_db in
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
        let sid1  = safe_getdomainsid domid in
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

let flask_getenforce () =
  Sec.getenforce itf

let flask_setenforce x =
  Sec.setenforce itf x

(** Node Accesses *)

(* Create audit data for a node access. *)
let node_access_audit_data domid path extra =
  [("domid", string_of_int domid); ("path",  path)] @ extra

(* Check access from a client domain against a Xenstore node. *)
let node_access dom_id node_path node_label av ad_extra =
  let ad = node_access_audit_data dom_id node_path ad_extra in
  let dom_sid = safe_getdomainsid dom_id in
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
  let ssid = safe_getdomainsid sdomid in
  let tsid = safe_getdomainsid tdomid in
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

(* does not raise Permission_denied on failure *)
let flask_retain_owner sdomid tdomid =
  let ad = [ ("sdomid", string_of_int sdomid)
           ; ("tdomid", string_of_int tdomid)] in
  let ssid = safe_getdomainsid sdomid in
  let tsid = safe_getdomainsid tdomid in
  Sec.has_perm itf ssid tsid Class.xenstore Perm.xenstore__retain_owner ad

let flask_make_priv_for sdomid tdomid =
  domid_access sdomid tdomid Perm.xenstore__make_priv_for

let flask_set_as_target sdomid tdomid =
  domid_access sdomid tdomid Perm.xenstore__set_as_target

let flask_set_target sdomid tdomid =
  domid_access sdomid tdomid Perm.xenstore__set_target

let get_node_value path =
  let results = Path_db.query path !g_path_db in
  match results with
  (* Not in path database, return none value. *)
  | [] -> Path_db.Value_none
  (* Use first result as sorted by the path DB query. *)
  | r :: _ ->
    match Path_db.(r.result_value) with
      (* should never happen, raise an exception *)
      | Path_db.Value_none ->
        raise (Failure "get_node_value: should not have result of Value_none")
      | Path_db.Value_str s -> Path_db.Value_str s
      | Path_db.Value_domid -> Path_db.Value_domid

let flask_get_value_type path =
  match get_node_value path with
  | Path_db.Value_str _ -> Xenstore_server.Xssm.PATH
  | Path_db.Value_domid -> Xenstore_server.Xssm.DOMID
  | Path_db.Value_none -> Xenstore_server.Xssm.NONE

let flask_check_domid domid =
  match OS.Domctl.getdomaininfo domid with
  | Some _ -> true
  | None   -> false
