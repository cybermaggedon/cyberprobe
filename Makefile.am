
SUBDIRS = src include config docs stix www tests init

ACLOCAL_AMFLAGS = -I m4

dist_doc_DATA = README COPYING

# Ensure make distcheck still works
DISTCHECK_CONFIGURE_FLAGS = \
  --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

