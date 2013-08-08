(*
 * security.mli --- Mandatory access control using Flask.
 *
 * Copyright (c) 2013, Galois, Inc.
 * All Rights Reserved.
 *
 * Written by James Bielman <jamesjb@galois.com>, 30 July 2013
 *)

open Types

(* Interface to the security server.  This module is parameterized
 * by the underlying security server (currently the Xen hypervisor
 * implementation in "OS.Flask"), and the set of security objects
 * in use, which are generated from the Flask policy and augmented
 * with data used for auditing. *)
module AVC : functor (Server : SecurityServer) -> sig
  (* Include the 'Server' interface. *)
  include module type of Server

  type interface
  (** A connection to the AVC. *)

  val interface_open : unit -> interface
  (** Open a connection to the AVC. *)

  val interface_close : interface -> unit
  (** Close a connection to the AVC. *)

  type audit_handler = string -> unit
  (** Function type for the audit log handler. *)

  val set_audit_handler : interface -> audit_handler -> unit
  (** Set the audit handler for an AVC interface. *)

  val getenforce : interface -> bool
  (** Return true if the security policy is being enforced. *)

  val setenforce : interface -> bool -> unit
  (** Set enforcing (true) or permissive (false) mode. *)

  val has_perm : interface -> Server.sid -> Server.sid ->
                Server.oclass -> Server.av ->
                Policy.audit_data -> bool
  (** Return true if an access request should be granted. *)

  (* Not exporting 'has_perm_noaudit' and 'audit' unless we need
   * them.  We'll just export 'has_perm' for now. *)
end
