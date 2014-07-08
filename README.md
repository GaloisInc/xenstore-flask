
# Flask Security Server for Mirage Xenstore

This package contains a pluggable security module for the
Mirage-based Xenstore that implements Flask-style mandatory
access control using the "libsepol" library.

The security policy consists of a standard SELinux binary
policy, augmented with a path database used to label
Xenstore nodes, and a context database used to translate
hypervisor security contexts to Xenstore security contexts.

