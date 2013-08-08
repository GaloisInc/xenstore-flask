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

val new_node_label : Path_db.t -> path -> context -> context
(** [new_node_label path_db path parent_context]

    Label a newly created node based on the path database
    and context of the (already existing) parent node.
    
    TODO: This interface will probably change to remove the
    path database argument, since "Xs_flask" should be able
    to have knowledge of the path database somehow. *)

(** {2 Node Accesses} *)

val flask_read : domid -> path -> context -> unit
(** Read a node, its permissions, security label, or
    list its children.

    Raises "Xenstore_server.Perms.Permission_denied" if access
    is denied, or returns unit if access is allowed. *)

val flask_write : domid -> path -> context -> unit
(** Write to a node, or create a child node.

    Raises "Xenstore_server.Perms.Permission_denied" if access
    is denied, or returns unit if access is allowed. *)
