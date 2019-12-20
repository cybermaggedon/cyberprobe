
SUBDIRS = src include config docs indicators stix www tests init subscribers \
	utils

ACLOCAL_AMFLAGS = -I m4

dist_doc_DATA = README.md COPYING

EXTRA_DIST=debian

# Ensure make distcheck still works
DISTCHECK_CONFIGURE_FLAGS = \
  --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

