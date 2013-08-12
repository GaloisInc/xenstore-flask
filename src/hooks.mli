(*
 * hooks.mli --- Xenstore security hooks.
 *
 * Copyright (C) 2013, Galois, Inc.
 * All Rights Reserved.
 *
 * Written by James Bielman <jamesjb@galois.com>, 8 August 2013
 *)

(** {2 Types} *)

type domid = int
(** A Xen domain ID. *)

type path = string
(** A path in the Xenstore tree. *)

type context = string
(** A security context string. *)

(** {2 Node Labelling} *)

val new_node_label : path -> context -> context
(** [new_node_label path parent_context]

    Label a newly created node based on the path database
    and context of the (already existing) parent node.
    
    TODO: This interface will probably change to remove the
    path database argument, since "Xs_flask" should be able
    to have knowledge of the path database somehow. *)

(** {2 Node Accesses} *)

val flask_read : domid -> path -> context -> unit
(** Read a node, its permissions, security label, or
    list its children. *)

val flask_write : domid -> path -> context -> unit
(** Write to a node, or create a child node. *)

val flask_create : domid -> path -> context -> unit
(** Create a child node with the given label. *)

val flask_delete : domid -> path -> context -> unit
(** Delete a node and all of its children. *)

val flask_chmod : domid -> path -> context -> string -> unit
(** Change DAC permissions on a node. *)

val flask_relabelfrom : domid -> path -> context -> unit
(** Allow objects of this type to be relabeled. *)

val flask_relabelto : domid -> path -> context -> unit
(** Allow objects to be relabeled to this type. *)

val flask_override : domid -> path -> context -> unit
(** Override the DAC permissions on a node. *)

(** {2 Node-Node Accesses} *)

val flask_bind : domid -> path -> context -> path -> context -> unit
(** Create a child node with the given label under a parent node. *)

val flask_transition : domid -> path -> context -> context -> unit
(** Explicitly change the security label of a node. *)

(** {2 Domain Accesses} *)

val flask_introduce : domid -> domid -> unit
(** Introduce a domain to Xenstore. *)

val flask_stat : domid -> domid -> unit
(** Query whether a domain is introduced. *)

val flask_release : domid -> domid -> unit
(** XS_RELEASE *)

val flask_resume : domid -> domid -> unit
(** XS_RESUME *)

val flask_chown_from : domid -> domid -> unit
(** Change ownership of a node, where old ownership is the
    target domain. *)

val flask_chown_to : domid -> domid -> unit
(** Change ownership of a node, where new ownership is the
    target domain. *)

val flask_chown_transition : domid -> domid -> unit
(** Allow a node to change ownership. *)

(* flask_retain_owner *)
(* flask_make_priv_for *)
(* flask_set_as_target *)
(* flask_set_target *)

