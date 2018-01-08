
SUBDIRS = src include config docs stix www tests init subscribers

ACLOCAL_AMFLAGS = -I m4

dist_doc_DATA = README COPYING

EXTRA_DIST=debian

# Ensure make distcheck still works
DISTCHECK_CONFIGURE_FLAGS = \
  --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

