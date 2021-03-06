(*
 * security.ml
 *
 * Copyright (c) 2013, Galois, Inc.
 * All Rights Reserved.
 *
 * Released under the BSD3 license.  See the file "LICENSE"
 * for details.
 *
 * Written by James Bielman <jamesjb@galois.com>, 30 July 2013
 *)

open Printf
open Types

module AVC (Server : SecurityServer) = struct
  include Server

  type audit_handler = string -> unit

  type interface = {
    mutable logger : audit_handler;
    mutable enforcing : bool;
  }

  (* Local cache of access checks *)
  let avc_cache_threshold = 512
  let avc_cache_reclaim = 16

  type avc_node = {
    resp : Server.av_decision;
    lru_hint : bool;
  }

  let avc_cache = Hashtbl.create avc_cache_threshold

  let avc_clear_cache () =
    Hashtbl.reset avc_cache

  let avc_reclaim_node avc_cache =
    let del = ref false in
    let num = ref 0 in
    let reclaim avc_req node =
      if !del
      then begin
        Hashtbl.remove avc_cache avc_req;
        incr num;
        if !num >= avc_cache_reclaim then raise Exit
      end;
      if node.lru_hint then del := true
    in
    Hashtbl.iter reclaim avc_cache;
    if !num < avc_cache_reclaim then Hashtbl.iter reclaim avc_cache

  let avc_add_node avc_cache av_req av_resp reclaimed =
    let node = { resp = av_resp; lru_hint = reclaimed; } in
    Hashtbl.replace avc_cache av_req node;
    av_resp

  let avc_search_node av_req =
    if Hashtbl.mem avc_cache av_req
    then Some ((Hashtbl.find avc_cache av_req).resp)
    else None

  let avc_lookup av_req =
    let node = avc_search_node av_req in
    match node with
    | Some (av_resp) -> av_resp
    | None ->
        let av_resp = access av_req in
        let reclaim =
          if Hashtbl.length avc_cache >= avc_cache_threshold
          then (avc_reclaim_node avc_cache; true)
          else (Hashtbl.length avc_cache) = 0
        in
        avc_add_node avc_cache av_req av_resp reclaim

  (* temporary default logger *)
  let default_logger = Printf.printf "%s\n%!"

  (* enforcing disabled by default *)
  let interface_open () = {
    logger = default_logger;
    enforcing = false;
  }

  let interface_close _ = ()

  let getenforce itf = itf.enforcing
  let setenforce itf x = itf.enforcing <- x

  (* Access Checks *)

  let set_audit_handler itf f = itf.logger <- f

  (* like "avc_has_perm_noaudit" *)
  let has_perm_noaudit itf av_req =
    let av_resp = avc_lookup av_req in
    let denied = Int32.logand av_req.req (Int32.lognot av_resp.allowed) in
    let allowed = if denied = 0l then true else not itf.enforcing in
    (allowed, av_resp)

  let lookup_class oclass =
    try
      List.assoc oclass Policy.Class.class_to_string
    with Not_found ->
      sprintf "0x%lx" oclass

  let lookup_av1 (av, s) (bit, name) =
    (Int32.logand av (Int32.lognot bit),
     if Int32.logand av bit <> 0l then
       s ^ " " ^ name
     else s)

  let lookup_av oclass av =
    try
      let perms = List.assoc oclass Policy.Perm.perm_to_string in
      let (av_rest, name) = List.fold_left lookup_av1 (av, "") perms in
      if av_rest <> 0l then
        "{" ^ name ^ sprintf " 0x%lx" av_rest ^ " }"
      else
        "{" ^ name ^ " }"
    with Not_found ->
      sprintf "{ 0x%lx }" av

  let dump_query ssid tsid tclass =
    let ssid_str = try "scontext=" ^ sid_to_context ssid with
                   | Failure _ -> "ssid=" ^ sid_to_string ssid in
    let tsid_str = try " tcontext=" ^ sid_to_context tsid with
                   | Failure _ -> " tsid=" ^ sid_to_string tsid in
    (* TODO: Need class name lookup here. *)
    let tclass_str = " tclass=" ^ lookup_class tclass in
    ssid_str ^ tsid_str ^ tclass_str

  (* like "avc_audit" --- returns 'unit'
   *
   * our audit messages should look something like this so we
   * can use standard selinux policy tools on them:
   *
   * avc: denied { getattr } for pid=2714 comm="ls"
   *  path="/usr/lib/locale/locale-archive"
   *  dev=dm-0 ino=353593 scontext=system_u:object_r:unlabeled_t:s0 
   *  tcontext=system_u:object_r:locale_t:s0 tclass=file
   *
   * (all on one line)
   *)
  let audit itf av_req av_resp allowed ad =
    let denied = Int32.logand av_req.req (Int32.lognot av_resp.allowed) in
    let (audited, need_audit) =
      if denied <> 0l then
        (denied, Int32.logand denied av_resp.audit_deny <> 0l)
      else if not allowed then
        (av_req.req, true)
      else
        (av_req.req, Int32.logand av_req.req av_resp.audit_allow <> 0l) in
    if need_audit then begin
      let msg = sprintf "avc: %s %s for %s %s"
                        (if denied <> 0l then "denied" else "granted")
                        (lookup_av av_req.tclass audited)
                        (Policy.audit_data_to_string ad)
                        (dump_query av_req.ssid av_req.tsid av_req.tclass) in
      itf.logger msg
    end

  (* blah, clean up req/resp stuff and make sure we're checking the
   * return code from the hypervisor.  i need lunch. *)
  let has_perm itf ssid tsid tclass req ad =
    let av_req = { ssid=ssid; tsid=tsid; tclass=tclass; req=req } in
    let (allowed, av_resp) = has_perm_noaudit itf av_req in
    audit itf av_req av_resp allowed ad;
    allowed

  (* Not exporting 'has_perm_noaudit' and 'audit' unless we need
   * them.  We'll just export 'has_perm' for now. *)
end
