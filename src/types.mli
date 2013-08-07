(*
 * types.mli --- Security server type declarations.
 *
 * Copyright (c) 2013, Galois, Inc.
 * All Rights Reserved.
 *
 * Written by James Bielman <jamesjb@galois.com>, 30 July 2013
 *)

(* The module type of a security server that manages a Flask
 * policy.  'OS.Flask' in Mirage is one instances of this module
 * type.  We will define another that does manages a policy in
 * "user space".  We may also need a way to combine security
 * servers with a parent/child relationship. *)
module type SecurityServer = sig
  (** {2 Security IDs and Contexts} *)

  type sid = int32
  (** A security identifier. *)

  val sid_to_string : sid -> string
  (** Convert a sid to a string for printing. *)

  type context = string
  (** A security context string. *)

  val context_to_sid : context -> sid
  (** Look up a context and return the sid, if it exists. *)

  val sid_to_context : sid -> context
  (** Look up a sid and return the context, if it exists. *)

  (** {2 Object Classes} *)

  type oclass = int32
  (** A class of object in the security server. *)

  val oclass_of_int32 : int32 -> oclass
  (** Initialize an 'oclass' from an 'int32'. *)

  val oclass_to_string : oclass -> string
  (** Convert an object class to a string for printing. *)

  (** {2 Access Vectors} *)

  type av = int32
  (** A set of permissions being requested or responded. *)

  val av_of_int32 : int32 -> av
  (** Initialize an 'av' from an 'int32'. *)

  val av_of_list : av list -> av
  (** Combine a list of access vectors into a single 'av'. *)

  val av_to_string : av -> string
  (** Convert an 'av' to a string for printing. *)

  (** {2 Access Checks} *)

  type av_request = {
    ssid : sid;         (* source sid *)
    tsid : sid;         (* target sid *)
    tclass : oclass;    (* target object class *)
    req : av;           (* requested access vector *)
  }
  (** An access request. *)

  type av_decision = {
    result : bool;      (* true if granted *)
    allowed : av;       (* allowed av *)
    audit_allow : av;   (* audit these allowed avs *)
    audit_deny : av;    (* audit these denied avs *)
  }
  (** An access decision. *)

  val access : av_request -> av_decision
  (** Perform an access check and return a decision.
    * Raises 'SecurityError' if any other error occurs. *)

  val create : sid -> sid -> oclass -> sid
  (** Perform an object creation transition decision. *)
end

(* Module containing object classes and access vectors used by
 * the application.  This interface is used by the 'AVC' module
 * to convert object classes and access vectors to strings for
 * auditing purposes.
 *
 * Modules that implement this interface will likely export
 * constants for the object classes and AVs defined as well.
 *
 * These modules will usually be generated automatically from
 * the policy definition. *)
module type SecurityObjects = sig
  type audit_data
  (** Opaque type for audit data attached with permission requests. *)

  val audit_data_to_string : audit_data -> string
  (** Convert audit data to a string for logging. *)

  module Class : sig
    val class_to_string : (int32 * string) list
  end

  module Perm : sig
    val perm_to_string : (int32 * (int32 * string) list) list
  end
end
