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
module AVC : functor (Server : SecurityServer) ->
             functor (Objects : SecurityObjects) -> sig
  (* Include the 'SecurityServer' interface, ensuring that
   * the types match. *)
  include SecurityServer
    with type sid = Server.sid
    and type context = Server.context
    and type oclass = Server.oclass
    and type av = Server.av
    and type av_request = Server.av_request
    and type av_decision = Server.av_decision

  (* Include the 'SecurityObjects' interface, ensuring that
   * the types match. *)
  include SecurityObjects
    with type audit_data = Objects.audit_data

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
                Server.oclass -> Server.av -> audit_data -> bool
  (** Return true if an access request should be granted. *)

  (* Not exporting 'has_perm_noaudit' and 'audit' unless we need
   * them.  We'll just export 'has_perm' for now. *)

(*
  val lookup_class : int32 -> string
  (** Look up the name of an object class.

      Returns the name of the object class or a hexadecimal
      representation of the numeric value if it is not found. *)

  val lookup_av : int32 -> int32 -> string
  (** Look up names of an access vector in the given class.

      Returns the names of known bits in 'av' separated by
      spaces, followed by the hex value of any remaining
      unknown permission bits. *)
*)
end
