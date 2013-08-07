(*
 * path_db_test.ml --- Xenstore path database test.
 *
 * Copyright (C) 2013, Galois, Inc.
 * All Rights Reserved.
 *
 * Written by James Bielman <jamesjb@galois.com>, 6 August 2013
 *)

open Printf

open Path_db

let const a _ = a

(* Convert a value to type and value strings for testing. *)
let value_to_strings value =
  match value with
  | Value_str   s -> ("STRING", s)
  | Value_domid   -> ("DOMID", "-")
  | Value_none    -> ("NONE", "-")

(* Print one node for debugging given the string of the parents
 * path, which always ends with the path separator. *)
let rec print_node1 path node =
  let (ty, value) = value_to_strings node.node_value in
  let name = path ^ node.node_name in
  (match node.node_value with
   | Value_none -> ()
   | _ -> printf "%-7d %-40s %-10s %s\n" node.node_metric name ty value);
  let new_path = if node.node_name = ""
                   then path
                   else path ^ node.node_name ^ "/" in
  StringMap.iter (const (print_node1 new_path)) node.node_children

(* Print the path database to the standard output. *)
let print_db db =
  printf "Path Database:\n\n";
  printf "%-7s %-40s %-10s %s\n" "metric" "path" "type" "value";
  printf "%s\n" (String.make 78 '-');
  print_node1 "/" db

(* Test Data *)
let entries =
  [ ("/local/domain",                  Value_str "local_domain_path_t")
  ; ("/local/domain/3",                Value_str "dom3_ctl_t")
  ; ("/local/domain/3/backend/vbd",    Value_str "dom3_disk_backend_t")
  ; ("/local/domain/3/backend/vbd/*",  Value_domid)
  ; ("/local/domain/3/backend/*",      Value_str "generic_dom3_backend_t")
  ; ("/local/domain/*",                Value_domid)
  ; ("/local/domain/*/device/vbd",     Value_str "disk_frontend_t")
  ; ("/local/domain/*/backend/vbd",    Value_str "disk_backend_t")
  ; ("/local/domain/*/backend/vbd/*",  Value_domid)
  ]

(* Format a query result to stdout for testing. *)
let print_query_result r =
  let (ty, s) = value_to_strings r.result_value in
  printf "%-7d %-10s %-30s {%s}\n" r.result_metric ty s 
         (String.concat " " r.result_wilds)

(* Run a query and print the results sorted by metric. *)
let query_test path db =
  printf "\nQuery Test for '%s':\n\n" path;
  match query path db with
  | [] ->
    printf "No results.\n"
  | results ->
    printf "%-7s %-10s %-30s %s\n" "metric" "type" "value" "wilds";
    printf "%s\n" (String.make 78 '-');
    List.iter print_query_result results

(* Main test program. *)
let _ =
  let db = build_db entries in
  print_db db;
  query_test "/" db;
  query_test "/local/domain/3" db;
  query_test "/local/domain/3/backend/vbd" db;
  query_test "/local/domain/4/backend/vbd" db;
  query_test "/local/domain/3/backend/vbd/5" db
