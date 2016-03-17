# Makefile.in generated by automake 1.11.6 from Makefile.am.
# docs/examples/Makefile.  Generated from Makefile.in by configure.

# Copyright (C) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002,
# 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Free Software
# Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.



#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
###########################################################################


am__make_dryrun = \
  { \
    am__dry=no; \
    case $$MAKEFLAGS in \
      *\\[\ \	]*) \
        echo 'am--echo: ; @echo "AM"  OK' | $(MAKE) -f - 2>/dev/null \
          | grep '^AM OK$$' >/dev/null || am__dry=yes;; \
      *) \
        for am__flg in $$MAKEFLAGS; do \
          case $$am__flg in \
            *=*|--*) ;; \
            *n*) am__dry=yes; break;; \
          esac; \
        done;; \
    esac; \
    test $$am__dry = yes; \
  }
pkgdatadir = $(datadir)/curl
pkgincludedir = $(includedir)/curl
pkglibdir = $(libdir)/curl
pkglibexecdir = $(libexecdir)/curl
am__cd = CDPATH="$${ZSH_VERSION+.}$(PATH_SEPARATOR)" && cd
install_sh_DATA = $(install_sh) -c -m 644
install_sh_PROGRAM = $(install_sh) -c
install_sh_SCRIPT = $(install_sh) -c
INSTALL_HEADER = $(INSTALL_DATA)
transform = $(program_transform_name)
NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
build_triplet = i686-pc-linux-gnu
host_triplet = i686-pc-linux-gnu
#am__append_1 = -DCURL_STATICLIB
bin_PROGRAMS = AC_DeviceService$(EXEEXT)
subdir = docs/examples
DIST_COMMON = $(srcdir)/Makefile.am $(srcdir)/Makefile.in
ACLOCAL_M4 = $(top_srcdir)/aclocal.m4
am__aclocal_m4_deps = $(top_srcdir)/m4/curl-compilers.m4 \
	$(top_srcdir)/m4/curl-confopts.m4 \
	$(top_srcdir)/m4/curl-functions.m4 \
	$(top_srcdir)/m4/curl-openssl.m4 \
	$(top_srcdir)/m4/curl-override.m4 \
	$(top_srcdir)/m4/curl-reentrant.m4 $(top_srcdir)/m4/libtool.m4 \
	$(top_srcdir)/m4/ltoptions.m4 $(top_srcdir)/m4/ltsugar.m4 \
	$(top_srcdir)/m4/ltversion.m4 $(top_srcdir)/m4/lt~obsolete.m4 \
	$(top_srcdir)/m4/xc-am-iface.m4 \
	$(top_srcdir)/m4/xc-cc-check.m4 \
	$(top_srcdir)/m4/xc-lt-iface.m4 \
	$(top_srcdir)/m4/xc-translit.m4 \
	$(top_srcdir)/m4/xc-val-flgs.m4 \
	$(top_srcdir)/m4/zz40-xc-ovr.m4 \
	$(top_srcdir)/m4/zz50-xc-ovr.m4 \
	$(top_srcdir)/m4/zz60-xc-ovr.m4 $(top_srcdir)/acinclude.m4 \
	$(top_srcdir)/configure.ac
am__configure_deps = $(am__aclocal_m4_deps) $(CONFIGURE_DEPENDENCIES) \
	$(ACLOCAL_M4)
mkinstalldirs = $(install_sh) -d
CONFIG_HEADER = $(top_builddir)/lib/curl_config.h \
	$(top_builddir)/include/curl/curlbuild.h
CONFIG_CLEAN_FILES =
CONFIG_CLEAN_VPATH_FILES =
am__installdirs = "$(DESTDIR)$(bindir)"
PROGRAMS = $(bin_PROGRAMS)
am_AC_DeviceService_OBJECTS = AC_DeviceService.$(OBJEXT) \
	cJSON.$(OBJEXT) rsa.$(OBJEXT) bignum.$(OBJEXT) md.$(OBJEXT) \
	sha1.$(OBJEXT) md_wrap.$(OBJEXT) HTTPClient.$(OBJEXT) \
	HTTPClientAuth.$(OBJEXT) HTTPClientString.$(OBJEXT) \
	HTTPClientWrapper.$(OBJEXT)
AC_DeviceService_OBJECTS = $(am_AC_DeviceService_OBJECTS)
AC_DeviceService_LDADD = $(LDADD)
AC_DeviceService_DEPENDENCIES =  \
	$(LIBDIR)/libcurl.la
#AC_DeviceService_DEPENDENCIES =  \
#	$(LIBDIR)/libcurl.la
AM_V_lt = $(am__v_lt_$(V))
am__v_lt_ = $(am__v_lt_$(AM_DEFAULT_VERBOSITY))
am__v_lt_0 = --silent
DEFAULT_INCLUDES = 
depcomp = $(SHELL) $(top_srcdir)/depcomp
am__depfiles_maybe = depfiles
am__mv = mv -f
COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
LTCOMPILE = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=compile $(CC) $(DEFS) \
	$(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) \
	$(AM_CFLAGS) $(CFLAGS)
AM_V_CC = $(am__v_CC_$(V))
am__v_CC_ = $(am__v_CC_$(AM_DEFAULT_VERBOSITY))
am__v_CC_0 = @echo "  CC    " $@;
AM_V_at = $(am__v_at_$(V))
am__v_at_ = $(am__v_at_$(AM_DEFAULT_VERBOSITY))
am__v_at_0 = @
CCLD = $(CC)
LINK = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
	$(LIBTOOLFLAGS) --mode=link $(CCLD) $(AM_CFLAGS) $(CFLAGS) \
	$(AM_LDFLAGS) $(LDFLAGS) -o $@
AM_V_CCLD = $(am__v_CCLD_$(V))
am__v_CCLD_ = $(am__v_CCLD_$(AM_DEFAULT_VERBOSITY))
am__v_CCLD_0 = @echo "  CCLD  " $@;
AM_V_GEN = $(am__v_GEN_$(V))
am__v_GEN_ = $(am__v_GEN_$(AM_DEFAULT_VERBOSITY))
am__v_GEN_0 = @echo "  GEN   " $@;
SOURCES = $(AC_DeviceService_SOURCES)
DIST_SOURCES = $(AC_DeviceService_SOURCES)
am__can_run_installinfo = \
  case $$AM_UPDATE_INFO_DIR in \
    n|no|NO) false;; \
    *) (install-info --version) >/dev/null 2>&1;; \
  esac
ETAGS = etags
CTAGS = ctags
DISTFILES = $(DIST_COMMON) $(DIST_SOURCES) $(TEXINFOS) $(EXTRA_DIST)
ACLOCAL = ${SHELL} /mnt/hgfs/curl-7.47.0/curl-7.47.0/missing --run aclocal-1.11
AMTAR = $${TAR-tar}
AM_DEFAULT_VERBOSITY = 0
AR = /usr/bin/ar
AS = as
AUTOCONF = ${SHELL} /mnt/hgfs/curl-7.47.0/curl-7.47.0/missing --run autoconf
AUTOHEADER = ${SHELL} /mnt/hgfs/curl-7.47.0/curl-7.47.0/missing --run autoheader
AUTOMAKE = ${SHELL} /mnt/hgfs/curl-7.47.0/curl-7.47.0/missing --run automake-1.11
AWK = mawk
BLANK_AT_MAKETIME = 
CC = gcc
CCDEPMODE = depmode=gcc3
CFLAGS = -O2 -Wno-system-headers
CFLAG_CURL_SYMBOL_HIDING = -fvisibility=hidden
CONFIGURE_OPTIONS = " '--with-ssl=/usr/local/ssl'"
CPP = gcc -E
CPPFLAGS = -I/usr/local/ssl/include
CPPFLAG_CURL_STATICLIB = 
CURLVERSION = 7.47.0
CURL_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
CURL_CFLAG_EXTRAS = 
CURL_DISABLE_DICT = 
CURL_DISABLE_FILE = 
CURL_DISABLE_FTP = 
CURL_DISABLE_GOPHER = 
CURL_DISABLE_HTTP = 
CURL_DISABLE_IMAP = 
CURL_DISABLE_LDAP = 1
CURL_DISABLE_LDAPS = 1
CURL_DISABLE_POP3 = 
CURL_DISABLE_PROXY = 
CURL_DISABLE_RTSP = 
CURL_DISABLE_SMB = 
CURL_DISABLE_SMTP = 
CURL_DISABLE_TELNET = 
CURL_DISABLE_TFTP = 
CURL_LT_SHLIB_VERSIONED_FLAVOUR = 
CURL_NETWORK_AND_TIME_LIBS = 
CURL_NETWORK_LIBS = 
CYGPATH_W = echo
DEFS = -DHAVE_CONFIG_H
DEPDIR = .deps
DLLTOOL = false
DSYMUTIL = 
DUMPBIN = 
ECHO_C = 
ECHO_N = -n
ECHO_T = 
EGREP = /bin/grep -E
ENABLE_SHARED = yes
ENABLE_STATIC = yes
EXEEXT = 
FGREP = /bin/grep -F
GREP = /bin/grep
HAVE_GNUTLS_SRP = 
HAVE_LDAP_SSL = 1
HAVE_LIBZ = 1
HAVE_OPENSSL_SRP = 1
IDN_ENABLED = 
INSTALL = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = ${INSTALL}
INSTALL_SCRIPT = ${INSTALL}
INSTALL_STRIP_PROGRAM = $(install_sh) -c -s
IPV6_ENABLED = 1
LD = /usr/bin/ld
LDFLAGS = -L/usr/local/ssl/lib
LIBCURL_LIBS = -lssl -lcrypto -lssl -lcrypto -lz
LIBMETALINK_CPPFLAGS = 
LIBMETALINK_LDFLAGS = 
LIBMETALINK_LIBS = 
LIBOBJS = 

# Prevent LIBS from being used for all link targets
LIBS = $(BLANK_AT_MAKETIME)
LIBTOOL = $(SHELL) $(top_builddir)/libtool
LIPO = 
LN_S = cp -pR
LTLIBOBJS = 
MAINT = #
MAKEINFO = ${SHELL} /mnt/hgfs/curl-7.47.0/curl-7.47.0/missing --run makeinfo
MANIFEST_TOOL = :
MANOPT = -man
MKDIR_P = /bin/mkdir -p
NM = /usr/bin/nm -B
NMEDIT = 
NROFF = /usr/bin/nroff
NSS_LIBS = 
OBJDUMP = objdump
OBJEXT = o
OTOOL = 
OTOOL64 = 
PACKAGE = curl
PACKAGE_BUGREPORT = a suitable curl mailing list: http://curl.haxx.se/mail/
PACKAGE_NAME = curl
PACKAGE_STRING = curl -
PACKAGE_TARNAME = curl
PACKAGE_URL = 
PACKAGE_VERSION = -
PATH_SEPARATOR = :
PERL = /usr/bin/perl
PKGADD_NAME = cURL - a client that groks URLs
PKGADD_PKG = HAXXcurl
PKGADD_VENDOR = curl.haxx.se
PKGCONFIG = no
RANDOM_FILE = /dev/urandom
RANLIB = ranlib
REQUIRE_LIB_DEPS = no
SED = /bin/sed
SET_MAKE = 
SHELL = /bin/bash
SSL_ENABLED = 1
SSL_LIBS = -lssl -lcrypto  
STRIP = strip
SUPPORT_FEATURES = SSL IPv6 UnixSockets libz NTLM NTLM_WB TLS-SRP
SUPPORT_PROTOCOLS = DICT FILE FTP FTPS GOPHER HTTP HTTPS IMAP IMAPS POP3 POP3S RTSP SMB SMBS SMTP SMTPS TELNET TFTP
USE_ARES = 
USE_AXTLS = 
USE_CYASSL = 
USE_DARWINSSL = 
USE_GNUTLS = 
USE_GNUTLS_NETTLE = 
USE_LIBRTMP = 
USE_LIBSSH2 = 
USE_MBEDTLS = 
USE_NGHTTP2 = 
USE_NSS = 
USE_OPENLDAP = 
USE_POLARSSL = 
USE_SCHANNEL = 
USE_UNIX_SOCKETS = 1
USE_WINDOWS_SSPI = 
VERSION = -
VERSIONNUM = 072f00
ZLIB_LIBS = -lz
ZSH_FUNCTIONS_DIR = ${prefix}/share/zsh/site-functions
abs_builddir = /mnt/hgfs/curl-7.47.0/curl-7.47.0/docs/examples
abs_srcdir = /mnt/hgfs/curl-7.47.0/curl-7.47.0/docs/examples
abs_top_builddir = /mnt/hgfs/curl-7.47.0/curl-7.47.0
abs_top_srcdir = /mnt/hgfs/curl-7.47.0/curl-7.47.0
ac_ct_AR = 
ac_ct_CC = gcc
ac_ct_DUMPBIN = 
am__include = include
am__leading_dot = .
am__quote = 
am__tar = $${TAR-tar} chof - "$$tardir"
am__untar = $${TAR-tar} xf -
bindir = ${exec_prefix}/bin
build = i686-pc-linux-gnu
build_alias = 
build_cpu = i686
build_os = linux-gnu
build_vendor = pc
builddir = .
datadir = ${datarootdir}
datarootdir = ${prefix}/share
docdir = ${datarootdir}/doc/${PACKAGE_TARNAME}
dvidir = ${docdir}
exec_prefix = ${prefix}
host = i686-pc-linux-gnu
host_alias = 
host_cpu = i686
host_os = linux-gnu
host_vendor = pc
htmldir = ${docdir}
includedir = ${prefix}/include
infodir = ${datarootdir}/info
install_sh = ${SHELL} /mnt/hgfs/curl-7.47.0/curl-7.47.0/install-sh
libdir = ${exec_prefix}/lib
libexecdir = ${exec_prefix}/libexec
libext = a
localedir = ${datarootdir}/locale
localstatedir = ${prefix}/var
mandir = ${datarootdir}/man
mkdir_p = /bin/mkdir -p
oldincludedir = /usr/include
pdfdir = ${docdir}
prefix = /usr/local
program_transform_name = s,x,x,
psdir = ${docdir}
sbindir = ${exec_prefix}/sbin
sharedstatedir = ${prefix}/com
srcdir = .
subdirs = 
sysconfdir = ${prefix}/etc
target_alias = 
top_build_prefix = ../../
top_builddir = ../..
top_srcdir = ../..
AUTOMAKE_OPTIONS = foreign nostdinc
EXTRA_DIST = README Makefile.example Makefile.inc Makefile.m32 \
	Makefile.netware makefile.dj $(COMPLICATED_EXAMPLES)


# Specify our include paths here, and do it relative to $(top_srcdir) and
# $(top_builddir), to ensure that these paths which belong to the library
# being currently built and tested are searched before the library which
# might possibly already be installed in the system.
#
# $(top_builddir)/include/curl for generated curlbuild.h included from curl.h
# $(top_builddir)/include for generated curlbuild.h inc. from lib/curl_setup.h
# $(top_srcdir)/include is for libcurl's external include files

# Avoid libcurl obsolete stuff
AM_CPPFLAGS = -I$(top_builddir)/include/curl \
	-I$(top_builddir)/include/httpclient -I$(top_builddir)/include \
	-I$(top_srcdir)/include -DCURL_NO_OLDIES $(am__append_1)
LIBDIR = $(top_builddir)/lib
LDADD = $(LIBDIR)/libcurl.la -lm -lcrypto -lssl

# Dependencies
#LDADD = $(LIBDIR)/libcurl.la -lm -lcrypto -lssl -lssl -lcrypto -lssl -lcrypto -lz
AC_DeviceService_SOURCES = AC_DeviceService.c \
                    cJSON.c \
                    rsa.c \
                    bignum.c \
                    md.c \
                    sha1.c \
                    md_wrap.c \
                    httpclient/HTTPClient.c \
                    httpclient/HTTPClientAuth.c \
                    httpclient/HTTPClientString.c \
                    httpclient/HTTPClientWrapper.c

all: all-am

.SUFFIXES:
.SUFFIXES: .c .lo .o .obj
$(srcdir)/Makefile.in: # $(srcdir)/Makefile.am  $(am__configure_deps)
	@for dep in $?; do \
	  case '$(am__configure_deps)' in \
	    *$$dep*) \
	      ( cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh ) \
	        && { if test -f $@; then exit 0; else break; fi; }; \
	      exit 1;; \
	  esac; \
	done; \
	echo ' cd $(top_srcdir) && $(AUTOMAKE) --foreign docs/examples/Makefile'; \
	$(am__cd) $(top_srcdir) && \
	  $(AUTOMAKE) --foreign docs/examples/Makefile
.PRECIOUS: Makefile
Makefile: $(srcdir)/Makefile.in $(top_builddir)/config.status
	@case '$?' in \
	  *config.status*) \
	    cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh;; \
	  *) \
	    echo ' cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe)'; \
	    cd $(top_builddir) && $(SHELL) ./config.status $(subdir)/$@ $(am__depfiles_maybe);; \
	esac;

$(top_builddir)/config.status: $(top_srcdir)/configure $(CONFIG_STATUS_DEPENDENCIES)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh

$(top_srcdir)/configure: # $(am__configure_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(ACLOCAL_M4): # $(am__aclocal_m4_deps)
	cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
$(am__aclocal_m4_deps):
install-binPROGRAMS: $(bin_PROGRAMS)
	@$(NORMAL_INSTALL)
	@list='$(bin_PROGRAMS)'; test -n "$(bindir)" || list=; \
	if test -n "$$list"; then \
	  echo " $(MKDIR_P) '$(DESTDIR)$(bindir)'"; \
	  $(MKDIR_P) "$(DESTDIR)$(bindir)" || exit 1; \
	fi; \
	for p in $$list; do echo "$$p $$p"; done | \
	sed 's/$(EXEEXT)$$//' | \
	while read p p1; do if test -f $$p || test -f $$p1; \
	  then echo "$$p"; echo "$$p"; else :; fi; \
	done | \
	sed -e 'p;s,.*/,,;n;h' -e 's|.*|.|' \
	    -e 'p;x;s,.*/,,;s/$(EXEEXT)$$//;$(transform);s/$$/$(EXEEXT)/' | \
	sed 'N;N;N;s,\n, ,g' | \
	$(AWK) 'BEGIN { files["."] = ""; dirs["."] = 1 } \
	  { d=$$3; if (dirs[d] != 1) { print "d", d; dirs[d] = 1 } \
	    if ($$2 == $$4) files[d] = files[d] " " $$1; \
	    else { print "f", $$3 "/" $$4, $$1; } } \
	  END { for (d in files) print "f", d, files[d] }' | \
	while read type dir files; do \
	    if test "$$dir" = .; then dir=; else dir=/$$dir; fi; \
	    test -z "$$files" || { \
	    echo " $(INSTALL_PROGRAM_ENV) $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=install $(INSTALL_PROGRAM) $$files '$(DESTDIR)$(bindir)$$dir'"; \
	    $(INSTALL_PROGRAM_ENV) $(LIBTOOL) $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=install $(INSTALL_PROGRAM) $$files "$(DESTDIR)$(bindir)$$dir" || exit $$?; \
	    } \
	; done

uninstall-binPROGRAMS:
	@$(NORMAL_UNINSTALL)
	@list='$(bin_PROGRAMS)'; test -n "$(bindir)" || list=; \
	files=`for p in $$list; do echo "$$p"; done | \
	  sed -e 'h;s,^.*/,,;s/$(EXEEXT)$$//;$(transform)' \
	      -e 's/$$/$(EXEEXT)/' `; \
	test -n "$$list" || exit 0; \
	echo " ( cd '$(DESTDIR)$(bindir)' && rm -f" $$files ")"; \
	cd "$(DESTDIR)$(bindir)" && rm -f $$files

clean-binPROGRAMS:
	@list='$(bin_PROGRAMS)'; test -n "$$list" || exit 0; \
	echo " rm -f" $$list; \
	rm -f $$list || exit $$?; \
	test -n "$(EXEEXT)" || exit 0; \
	list=`for p in $$list; do echo "$$p"; done | sed 's/$(EXEEXT)$$//'`; \
	echo " rm -f" $$list; \
	rm -f $$list
AC_DeviceService$(EXEEXT): $(AC_DeviceService_OBJECTS) $(AC_DeviceService_DEPENDENCIES) $(EXTRA_AC_DeviceService_DEPENDENCIES) 
	@rm -f AC_DeviceService$(EXEEXT)
	$(AM_V_CCLD)$(LINK) $(AC_DeviceService_OBJECTS) $(AC_DeviceService_LDADD) $(LIBS)

mostlyclean-compile:
	-rm -f *.$(OBJEXT)

distclean-compile:
	-rm -f *.tab.c

include ./$(DEPDIR)/AC_DeviceService.Po
include ./$(DEPDIR)/HTTPClient.Po
include ./$(DEPDIR)/HTTPClientAuth.Po
include ./$(DEPDIR)/HTTPClientString.Po
include ./$(DEPDIR)/HTTPClientWrapper.Po
include ./$(DEPDIR)/bignum.Po
include ./$(DEPDIR)/cJSON.Po
include ./$(DEPDIR)/md.Po
include ./$(DEPDIR)/md_wrap.Po
include ./$(DEPDIR)/rsa.Po
include ./$(DEPDIR)/sha1.Po

.c.o:
	$(AM_V_CC)$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(AM_V_at)$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	$(AM_V_CC)source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(COMPILE) -c $<

.c.obj:
	$(AM_V_CC)$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ `$(CYGPATH_W) '$<'`
	$(AM_V_at)$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po
#	$(AM_V_CC)source='$<' object='$@' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(COMPILE) -c `$(CYGPATH_W) '$<'`

.c.lo:
	$(AM_V_CC)$(LTCOMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(AM_V_at)$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Plo
#	$(AM_V_CC)source='$<' object='$@' libtool=yes \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(LTCOMPILE) -c -o $@ $<

HTTPClient.o: httpclient/HTTPClient.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT HTTPClient.o -MD -MP -MF $(DEPDIR)/HTTPClient.Tpo -c -o HTTPClient.o `test -f 'httpclient/HTTPClient.c' || echo '$(srcdir)/'`httpclient/HTTPClient.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/HTTPClient.Tpo $(DEPDIR)/HTTPClient.Po
#	$(AM_V_CC)source='httpclient/HTTPClient.c' object='HTTPClient.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o HTTPClient.o `test -f 'httpclient/HTTPClient.c' || echo '$(srcdir)/'`httpclient/HTTPClient.c

HTTPClient.obj: httpclient/HTTPClient.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT HTTPClient.obj -MD -MP -MF $(DEPDIR)/HTTPClient.Tpo -c -o HTTPClient.obj `if test -f 'httpclient/HTTPClient.c'; then $(CYGPATH_W) 'httpclient/HTTPClient.c'; else $(CYGPATH_W) '$(srcdir)/httpclient/HTTPClient.c'; fi`
	$(AM_V_at)$(am__mv) $(DEPDIR)/HTTPClient.Tpo $(DEPDIR)/HTTPClient.Po
#	$(AM_V_CC)source='httpclient/HTTPClient.c' object='HTTPClient.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o HTTPClient.obj `if test -f 'httpclient/HTTPClient.c'; then $(CYGPATH_W) 'httpclient/HTTPClient.c'; else $(CYGPATH_W) '$(srcdir)/httpclient/HTTPClient.c'; fi`

HTTPClientAuth.o: httpclient/HTTPClientAuth.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT HTTPClientAuth.o -MD -MP -MF $(DEPDIR)/HTTPClientAuth.Tpo -c -o HTTPClientAuth.o `test -f 'httpclient/HTTPClientAuth.c' || echo '$(srcdir)/'`httpclient/HTTPClientAuth.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/HTTPClientAuth.Tpo $(DEPDIR)/HTTPClientAuth.Po
#	$(AM_V_CC)source='httpclient/HTTPClientAuth.c' object='HTTPClientAuth.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o HTTPClientAuth.o `test -f 'httpclient/HTTPClientAuth.c' || echo '$(srcdir)/'`httpclient/HTTPClientAuth.c

HTTPClientAuth.obj: httpclient/HTTPClientAuth.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT HTTPClientAuth.obj -MD -MP -MF $(DEPDIR)/HTTPClientAuth.Tpo -c -o HTTPClientAuth.obj `if test -f 'httpclient/HTTPClientAuth.c'; then $(CYGPATH_W) 'httpclient/HTTPClientAuth.c'; else $(CYGPATH_W) '$(srcdir)/httpclient/HTTPClientAuth.c'; fi`
	$(AM_V_at)$(am__mv) $(DEPDIR)/HTTPClientAuth.Tpo $(DEPDIR)/HTTPClientAuth.Po
#	$(AM_V_CC)source='httpclient/HTTPClientAuth.c' object='HTTPClientAuth.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o HTTPClientAuth.obj `if test -f 'httpclient/HTTPClientAuth.c'; then $(CYGPATH_W) 'httpclient/HTTPClientAuth.c'; else $(CYGPATH_W) '$(srcdir)/httpclient/HTTPClientAuth.c'; fi`

HTTPClientString.o: httpclient/HTTPClientString.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT HTTPClientString.o -MD -MP -MF $(DEPDIR)/HTTPClientString.Tpo -c -o HTTPClientString.o `test -f 'httpclient/HTTPClientString.c' || echo '$(srcdir)/'`httpclient/HTTPClientString.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/HTTPClientString.Tpo $(DEPDIR)/HTTPClientString.Po
#	$(AM_V_CC)source='httpclient/HTTPClientString.c' object='HTTPClientString.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o HTTPClientString.o `test -f 'httpclient/HTTPClientString.c' || echo '$(srcdir)/'`httpclient/HTTPClientString.c

HTTPClientString.obj: httpclient/HTTPClientString.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT HTTPClientString.obj -MD -MP -MF $(DEPDIR)/HTTPClientString.Tpo -c -o HTTPClientString.obj `if test -f 'httpclient/HTTPClientString.c'; then $(CYGPATH_W) 'httpclient/HTTPClientString.c'; else $(CYGPATH_W) '$(srcdir)/httpclient/HTTPClientString.c'; fi`
	$(AM_V_at)$(am__mv) $(DEPDIR)/HTTPClientString.Tpo $(DEPDIR)/HTTPClientString.Po
#	$(AM_V_CC)source='httpclient/HTTPClientString.c' object='HTTPClientString.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o HTTPClientString.obj `if test -f 'httpclient/HTTPClientString.c'; then $(CYGPATH_W) 'httpclient/HTTPClientString.c'; else $(CYGPATH_W) '$(srcdir)/httpclient/HTTPClientString.c'; fi`

HTTPClientWrapper.o: httpclient/HTTPClientWrapper.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT HTTPClientWrapper.o -MD -MP -MF $(DEPDIR)/HTTPClientWrapper.Tpo -c -o HTTPClientWrapper.o `test -f 'httpclient/HTTPClientWrapper.c' || echo '$(srcdir)/'`httpclient/HTTPClientWrapper.c
	$(AM_V_at)$(am__mv) $(DEPDIR)/HTTPClientWrapper.Tpo $(DEPDIR)/HTTPClientWrapper.Po
#	$(AM_V_CC)source='httpclient/HTTPClientWrapper.c' object='HTTPClientWrapper.o' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o HTTPClientWrapper.o `test -f 'httpclient/HTTPClientWrapper.c' || echo '$(srcdir)/'`httpclient/HTTPClientWrapper.c

HTTPClientWrapper.obj: httpclient/HTTPClientWrapper.c
	$(AM_V_CC)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -MT HTTPClientWrapper.obj -MD -MP -MF $(DEPDIR)/HTTPClientWrapper.Tpo -c -o HTTPClientWrapper.obj `if test -f 'httpclient/HTTPClientWrapper.c'; then $(CYGPATH_W) 'httpclient/HTTPClientWrapper.c'; else $(CYGPATH_W) '$(srcdir)/httpclient/HTTPClientWrapper.c'; fi`
	$(AM_V_at)$(am__mv) $(DEPDIR)/HTTPClientWrapper.Tpo $(DEPDIR)/HTTPClientWrapper.Po
#	$(AM_V_CC)source='httpclient/HTTPClientWrapper.c' object='HTTPClientWrapper.obj' libtool=no \
#	DEPDIR=$(DEPDIR) $(CCDEPMODE) $(depcomp) \
#	$(AM_V_CC_no)$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -c -o HTTPClientWrapper.obj `if test -f 'httpclient/HTTPClientWrapper.c'; then $(CYGPATH_W) 'httpclient/HTTPClientWrapper.c'; else $(CYGPATH_W) '$(srcdir)/httpclient/HTTPClientWrapper.c'; fi`

mostlyclean-libtool:
	-rm -f *.lo

clean-libtool:
	-rm -rf .libs _libs

ID: $(HEADERS) $(SOURCES) $(LISP) $(TAGS_FILES)
	list='$(SOURCES) $(HEADERS) $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '{ files[$$0] = 1; nonempty = 1; } \
	      END { if (nonempty) { for (i in files) print i; }; }'`; \
	mkid -fID $$unique
tags: TAGS

TAGS:  $(HEADERS) $(SOURCES)  $(TAGS_DEPENDENCIES) \
		$(TAGS_FILES) $(LISP)
	set x; \
	here=`pwd`; \
	list='$(SOURCES) $(HEADERS)  $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '{ files[$$0] = 1; nonempty = 1; } \
	      END { if (nonempty) { for (i in files) print i; }; }'`; \
	shift; \
	if test -z "$(ETAGS_ARGS)$$*$$unique"; then :; else \
	  test -n "$$unique" || unique=$$empty_fix; \
	  if test $$# -gt 0; then \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      "$$@" $$unique; \
	  else \
	    $(ETAGS) $(ETAGSFLAGS) $(AM_ETAGSFLAGS) $(ETAGS_ARGS) \
	      $$unique; \
	  fi; \
	fi
ctags: CTAGS
CTAGS:  $(HEADERS) $(SOURCES)  $(TAGS_DEPENDENCIES) \
		$(TAGS_FILES) $(LISP)
	list='$(SOURCES) $(HEADERS)  $(LISP) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '{ files[$$0] = 1; nonempty = 1; } \
	      END { if (nonempty) { for (i in files) print i; }; }'`; \
	test -z "$(CTAGS_ARGS)$$unique" \
	  || $(CTAGS) $(CTAGSFLAGS) $(AM_CTAGSFLAGS) $(CTAGS_ARGS) \
	     $$unique

GTAGS:
	here=`$(am__cd) $(top_builddir) && pwd` \
	  && $(am__cd) $(top_srcdir) \
	  && gtags -i $(GTAGS_ARGS) "$$here"

distclean-tags:
	-rm -f TAGS ID GTAGS GRTAGS GSYMS GPATH tags

distdir: $(DISTFILES)
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	  dist_files=`for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t"`; \
	case $$dist_files in \
	  */*) $(MKDIR_P) `echo "$$dist_files" | \
			   sed '/\//!d;s|^|$(distdir)/|;s,/[^/]*$$,,' | \
			   sort -u` ;; \
	esac; \
	for file in $$dist_files; do \
	  if test -f $$file || test -d $$file; then d=.; else d=$(srcdir); fi; \
	  if test -d $$d/$$file; then \
	    dir=`echo "/$$file" | sed -e 's,/[^/]*$$,,'`; \
	    if test -d "$(distdir)/$$file"; then \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    if test -d $(srcdir)/$$file && test $$d != $(srcdir); then \
	      cp -fpR $(srcdir)/$$file "$(distdir)$$dir" || exit 1; \
	      find "$(distdir)/$$file" -type d ! -perm -700 -exec chmod u+rwx {} \;; \
	    fi; \
	    cp -fpR $$d/$$file "$(distdir)$$dir" || exit 1; \
	  else \
	    test -f "$(distdir)/$$file" \
	    || cp -p $$d/$$file "$(distdir)/$$file" \
	    || exit 1; \
	  fi; \
	done
check-am: all-am
check: check-am
all-am: Makefile $(PROGRAMS)
installdirs:
	for dir in "$(DESTDIR)$(bindir)"; do \
	  test -z "$$dir" || $(MKDIR_P) "$$dir"; \
	done
install: install-am
install-exec: install-exec-am
install-data: install-data-am
uninstall: uninstall-am

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am

installcheck: installcheck-am
install-strip:
	if test -z '$(STRIP)'; then \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	      install; \
	else \
	  $(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	    install_sh_PROGRAM="$(INSTALL_STRIP_PROGRAM)" INSTALL_STRIP_FLAG=-s \
	    "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'" install; \
	fi
mostlyclean-generic:

clean-generic:

distclean-generic:
	-test -z "$(CONFIG_CLEAN_FILES)" || rm -f $(CONFIG_CLEAN_FILES)
	-test . = "$(srcdir)" || test -z "$(CONFIG_CLEAN_VPATH_FILES)" || rm -f $(CONFIG_CLEAN_VPATH_FILES)

maintainer-clean-generic:
	@echo "This command is intended for maintainers to use"
	@echo "it deletes files that may require special tools to rebuild."
clean: clean-am

clean-am: clean-binPROGRAMS clean-generic clean-libtool mostlyclean-am

distclean: distclean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
distclean-am: clean-am distclean-compile distclean-generic \
	distclean-tags

dvi: dvi-am

dvi-am:

html: html-am

html-am:

info: info-am

info-am:

install-data-am:

install-dvi: install-dvi-am

install-dvi-am:

install-exec-am: install-binPROGRAMS

install-html: install-html-am

install-html-am:

install-info: install-info-am

install-info-am:

install-man:

install-pdf: install-pdf-am

install-pdf-am:

install-ps: install-ps-am

install-ps-am:

installcheck-am:

maintainer-clean: maintainer-clean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
maintainer-clean-am: distclean-am maintainer-clean-generic

mostlyclean: mostlyclean-am

mostlyclean-am: mostlyclean-compile mostlyclean-generic \
	mostlyclean-libtool

pdf: pdf-am

pdf-am:

ps: ps-am

ps-am:

uninstall-am: uninstall-binPROGRAMS

.MAKE: install-am install-strip

.PHONY: CTAGS GTAGS all all-am check check-am clean clean-binPROGRAMS \
	clean-generic clean-libtool ctags distclean distclean-compile \
	distclean-generic distclean-libtool distclean-tags distdir dvi \
	dvi-am html html-am info info-am install install-am \
	install-binPROGRAMS install-data install-data-am install-dvi \
	install-dvi-am install-exec install-exec-am install-html \
	install-html-am install-info install-info-am install-man \
	install-pdf install-pdf-am install-ps install-ps-am \
	install-strip installcheck installcheck-am installdirs \
	maintainer-clean maintainer-clean-generic mostlyclean \
	mostlyclean-compile mostlyclean-generic mostlyclean-libtool \
	pdf pdf-am ps ps-am tags uninstall uninstall-am \
	uninstall-binPROGRAMS


# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
