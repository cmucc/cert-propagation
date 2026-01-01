prefix = /usr/local
sbindir = $(prefix)/sbin
mandir = $(prefix)/share/man
privatepythondir = $(prefix)/share/cclub-cert-receive

INSTALL = install
PYTHON = python3

-include config.mk

build : build-nonpython build-python

build-nonpython :

build-python : build-python-stamp wrapper/cert_receive.py

.PHONY : build build-nonpython build-python

check : check-nonpython check-python

check-nonpython :

check-python : build-python
	USE_FAKEROOT=; \
	if [ -z "$$FAKEROOTKEY" ] && command -v fakeroot >/dev/null; then \
	    USE_FAKEROOT=fakeroot; \
	fi; \
	cd build/lib && $$USE_FAKEROOT $(PYTHON) -m pytest ../../tests

.PHONY : check check-nonpython check-python

build-python-stamp : cert_receive/*.py pyproject.toml
	$(PYTHON) -m build --no-isolation --skip-dependency-check --wheel
	touch $@

pythonabspath = $(abspath $(shell command -v $(PYTHON)))
privatepythonstr = $(shell echo -n 'r"'; echo -n $(privatepythondir); echo '"')

wrapper/cert_receive.py : wrapper/cert_receive.py.in
	sed -e '/^#shebang#$$/{' -e 'i\' \
	    -e '#! $(pythonabspath)' -e 'd' -e '}' \
	    -e '/^#path_manipulation#$$/{' -e 'i\' \
	    -e 'sys.path$(if $(privatepythondir),[0] = $(privatepythonstr),.pop(0))' \
	    -e 'd' -e '}' $< > $@ || \
	{ rm -f $@; exit 1; }

clean :
	rm -rf build build-python-stamp cert_receive.egg-info dist pip_install_*
	find . -path ./.tox -prune -o \
	       -name __pycache__ -type d -prune -exec rm -rf {} \;
	rm -f wrapper/cert_receive.py

distclean : clean
	rm -rf .tox config.mk

.PHONY : clean distclean

install : install-nonpython install-python

install-nonpython :
	$(INSTALL) -d $(DESTDIR)$(sbindir) $(DESTDIR)$(mandir)/man5 $(DESTDIR)$(mandir)/man8
	$(INSTALL) -t $(DESTDIR)$(sbindir) -m 0755 certbot_send.sh
	$(INSTALL) -t $(DESTDIR)$(mandir)/man5 -m 0644 cert_receive.json.5 certbot_send.5
	$(INSTALL) -t $(DESTDIR)$(mandir)/man8 -m 0644 cert_receive.py.8 certbot_send.sh.8

pip_install = $(PYTHON) -m pip install --no-deps --no-index

install-python : build-python
ifeq ($(privatepythondir),)
	$(INSTALL) -d $(DESTDIR)$(prefix)
	# This is klugy and complicated to handle Debian-based Python
	# installations that append "/local" to the specified install
	# prefix.
	set -e; \
	tmp=`mktemp -d ./pip_install_XXXXXX`; \
	trap 'rm -rf "$$tmp"' EXIT; \
	$(pip_install) --prefix "$$tmp" dist/*.whl; \
	from="$$tmp"; \
	if [ -d "$$tmp/local" ]; then \
	    from="$$tmp/local"; \
	fi; \
	rm -rf "$$from/bin"; \
	cp -t $(DESTDIR)$(prefix) -a "$$from"/*
else
	$(INSTALL) -d $(DESTDIR)$(privatepythondir)
	$(pip_install) --target $(DESTDIR)$(privatepythondir) dist/*.whl
	rm -rf $(DESTDIR)$(privatepythondir)/bin
endif
	$(INSTALL) -d $(DESTDIR)$(sbindir)
	$(INSTALL) -t $(DESTDIR)$(sbindir) -m 0755 wrapper/cert_receive.py

.PHONY : install install-nonpython install-python
