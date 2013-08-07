(*
 * policy.ml --- Security policy objects.
 *
 * Copyright (C) 2013, Galois, Inc.
 * All Rights Reserved.
 *
 * Written by James Bielman <jamesjb@galois.com>, 26 July 2013
 *)

type audit_data = unit

let audit_data_to_string () = "unknown"

include Policy_gen
