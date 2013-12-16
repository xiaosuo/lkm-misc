.PHONY: modules modules_install modules_clean

modules:
	if test -n "$(kbuilddir)"; then $(MAKE) -C $(kbuilddir) M=${abs_srcdir} $@; fi

modules_install:
	if test -n "$(kbuilddir)"; then $(MAKE) -C $(kbuilddir) M=${abs_srcdir} INSTALL_MOD_PATH=${DESTDIR} $@; fi

modules_clean:
	if test -n "$(kbuilddir)"; then $(MAKE) -C $(kbuilddir) M=${abs_srcdir} clean; fi

all-local: modules

install-exec-local: modules_install

clean-local: modules_clean

uninstall-local:
	$(RM) ${DESTDIR}/lib/modules/`uname -r`/extra/bnotify.ko

EXTRA_DIST = \
	     Kbuild \
	     bnotify.c
