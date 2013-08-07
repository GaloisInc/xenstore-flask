#! /bin/sh
#
# gen-policy.sh --- Generate "src/policy_gen.ml".
#
# Copyright (C) 2013, Galois, Inc.
# All Rights Reserved.
#
# Written by James Bielman <jamesjb@galois.com>, 7 August 2013
#

set -e

if [ $# -ne 2 ]; then
  echo "Usage: $0 DOMAIN_BUILDER_PATH POLICY_CONF" 1>&2
  exit 1
fi

DOMAIN_BUILDER=$1
POLICY=$2
GENFLASK=$DOMAIN_BUILDER/bin/genflask

if [ ! -d $DOMAIN_BUILDER ]; then
  echo "Error: Directory '$DOMAIN_BUILDER' does not exist." 1>&2
  exit 1
fi

if [ ! -x $GENFLASK ]; then
  echo "Error: $GENFLASK does not exist." 1>&2
  exit 1
fi

if [ ! -f $POLICY ]; then
  echo "Error: $POLICY does not exist." 1>&2
  exit 1
fi

$GENFLASK < $POLICY > src/policy_gen.ml

