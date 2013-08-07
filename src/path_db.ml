(*
 * path_db.ml --- Xenstore path database.
 *
 * Copyright (C) 2013, Galois, Inc.
 * All Rights Reserved.
 *
 * Written by James Bielman <jamesjb@galois.com>, 6 August 2013
 *)

(* An associative map with string keys. *)
module StringMap = Map.Make (String)

(* Node value type, a security context or use the domain ID. 
 *
 * The type 'Value_none' is for nodes that aren't actually
 * in the path database but exist because they have children. *)
type node_value
  = Value_str of string
  | Value_domid
  | Value_none

(* The path database is stored as a tree of type "node".  There is
 * a single root node with name "".
 *
 * Paths are passed in a strings, and split on "/", allowing empty
 * path components which will only match the root node.  This means
 * that double slashes are not allowed in path names. *)
type node = {
  node_name : string;                (* path element string *)
  node_value : node_value;           (* node's value *)
  node_children : node StringMap.t;
  node_metric : int;
}

type t = node

(* The empty node. *)
let empty = {
  node_name = "";
  node_value = Value_none;
  node_children = StringMap.empty;
  node_metric = 0;
}

(* Return true if "node" has a wildcard name. *)
let is_wild node = node.node_name = "*"

(** Path Operations *)

(* Split a path string into a list of path components.  An
 * absolute path will begin with an initial empty string. *)
let path_split s =
  Str.split_delim (Str.regexp "/") s

(* Convert a path to a string for debugging. *)
let path_to_string path =
  let quote s = "\"" ^ s ^ "\"" in
  "[" ^ String.concat " " (List.map quote path) ^ "]"

(** Insertion *)

(* Create a new node with a name and value. *)
let new_node name value = {
  node_name = name;
  node_value = value;
  node_children = StringMap.empty;
  node_metric = 0
}

(** Update a node with a new value and metric. *)
let update_node node value metric =
  {node with node_value = value; node_metric = metric}

(* Find an immediate child node with an exact name match. *)
let find_child node name =
  StringMap.find name node.node_children

(* Find an immediate child node or create a new one. *)
let find_or_create_child node name =
  try
    find_child node name
  with Not_found ->
    new_node name Value_none

(* Find or create a child node of 'node' called 'name', transform
 * it by calling 'f', and return 'node' with the transformed child
 * updated in its child map. *)
let map_child node name f =
  let child = f (find_or_create_child node name) in
  {node with node_children=StringMap.add name child node.node_children}

(* Worker for 'insert'.  Creates intermediate children along
 * the path until we get to the end, then updates the child
 * with the given value and metric. *)
let rec insert_path paths value metric node =
  match paths with
  | [] ->
    update_node node value metric
  | name :: rest ->
    map_child node name (insert_path rest value metric)

(* Insert a new entry into the path database. *)
let insert path value metric db =
  let paths = path_split path in
  match paths with
  | "" :: rest -> insert_path rest value metric db
  | _ -> raise (Failure ("invalid path: " ^ path))

(** Querying *)

(* A query result. *)
type result = {
  result_value : node_value;
  result_metric : int;
  result_wilds : string list;
}

(* Return true if 'name' matches 'node'. *)
let name_eq name node =
  if node.node_name = "*" then
    true
  else
    node.node_name = name

(* Combine two result sets. *)
let combine_results r1 r2 =
  List.append r1 r2

(* Worker for 'query'.  Builds a list of results by walking down
 * the path and the node database.  We accumulate matched wildcards
 * along the way down. *)
let rec query_child paths wilds _ node results =
  combine_results results (query1 paths node wilds)
and query1 paths node wilds =
  match paths with
  | [] ->
    (match node.node_value with
     | Value_none -> []
     | v -> [{result_value=v; result_metric=node.node_metric;
              result_wilds=List.rev wilds}])
  | name :: rest ->
    if name_eq name node then
      let new_wilds = if is_wild node then name :: wilds else wilds in
      match rest with
      (* end of path, don't search children *)
      | [] -> query1 rest node new_wilds
      (* not end of path, combine results from each child *)
      | _ -> StringMap.fold (query_child rest new_wilds)
                            node.node_children []
    else []

(* Compare two query results by metric. *)
let metric_compare a b =
  compare a.result_metric b.result_metric

(* Query the path database, returning all the results that match.
 * The results are sorted by metric in ascending order. *)
let query path db =
  List.sort metric_compare (query1 (path_split path) db [])

(* Build a path database from a list of tuples of paths and values. *)
let build_db table =
  let go (db, n) (path, value) = (insert path value n db, n+1) in
  fst (List.fold_left go (empty, 0) table)
