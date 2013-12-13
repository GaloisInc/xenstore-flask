#
# Makefile
#
# Copyright (C) 2013, Galois, Inc.
# All Rights Reserved.
#

FLASK_FILES_PRE   := security_classes initial_sids access_vectors
FLASK_FILES_POST  := initial_sid_defs

POLICY_FILES      := xenstore.if xenstore.te
POLICY_VERSION    := 24
POLICY            := xenstore.$(POLICY_VERSION)

CHECKPOLICY       := checkpolicy -c $(POLICY_VERSION)
ALL_FILES         := $(FLASK_FILES_PRE) $(POLICY_FILES) $(FLASK_FILES_POST)

all: $(POLICY) include/flask.h

$(POLICY): policy.conf
	$(CHECKPOLICY) -o $@ policy.conf

policy.conf: $(ALL_FILES) Makefile
	m4 -D self_contained_policy -s $(ALL_FILES) > $@

include/flask.h: $(ALL_FILES)
	test -d include || mkdir include
	python flask.py -a access_vectors -i initial_sids -s security_classes -u -o include

clean:
	rm -rf include policy.conf $(POLICY)
