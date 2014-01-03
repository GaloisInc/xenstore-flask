(*
 * sec_server.ml --- Xenstore security server.
 *
 * Copyright (c) 2014, Galois, Inc.
 * All Rights Reserved.
 *
 * Written by James Bielman <jamesjb@galois.com>, 2 January 2014
 *)

open Printf

(* Type Definitions *)

type sid = int32
type context = string
type oclass = int32
type av = int32

type av_request = {
  ssid : sid;
  tsid : sid;
  tclass : oclass;
  req : av;
}

type av_decision = {
  result : bool;
  allowed : av;
  audit_allow : av;
  audit_deny : av;
}

(* Security IDs and Contexts *)

let sid_to_string = Int32.to_string

let context_to_sid = OS.Sepol.context_to_sid
let sid_to_context = OS.Sepol.sid_to_context

(* Object Classes *)

let oclass_of_int32 x = x
let oclass_to_string = Int32.to_string

(* Access Vectors *)

let av_of_int32 x = x
let av_of_list = List.fold_left Int32.logor 0l
let av_to_string = sprintf "0x%lx"

(* Access Checks *)

let access avreq =
  let avd = OS.Sepol.compute_av avreq.ssid avreq.tsid avreq.tclass avreq.req in
  (* we are translating between two very similar data structures
   * here, hence the explicit record field qualification... *)
  { result = OS.Sepol.(avd.allowed) != 0l;
    allowed = OS.Sepol.(avd.allowed);
    audit_allow = OS.Sepol.(avd.auditallow);
    audit_deny = OS.Sepol.(avd.auditdeny); }

let create = OS.Sepol.transition_sid
