PYTHON = python3

all : wrapper/cert_receive.py

pythonabspath = $(abspath $(shell command -v $(PYTHON)))
privatepythonstr = $(shell echo -n 'r"/usr/share/cclub-cert-receive"')

wrapper/cert_receive.py : wrapper/cert_receive.py.in
	sed -e '/^#shebang#$$/{' -e 'i\' \
	    -e '#! $(pythonabspath)' -e 'd' -e '}' \
	    -e '/^#path_manipulation#$$/{' -e 'i\' \
	    -e 'sys.path[0] = $(privatepythonstr)' \
	    -e 'd' -e '}' $< > $@ || \
	{ rm -f $@; exit 1; }

check :
	USE_FAKEROOT=; \
	if [ -z "$$FAKEROOTKEY" ] && command -v fakeroot >/dev/null; then \
	    USE_FAKEROOT=fakeroot; \
	fi; \
	$$USE_FAKEROOT $(PYTHON) -m pytest

clean :
	rm -rf build cert_receive.egg-info dist
	find . -path ./.tox -prune -o \
	       -name __pycache__ -type d -prune -exec rm -rf {} \;
	rm -f wrapper/cert_receive.py

distclean : clean
	rm -rf .tox

install :

.PHONY : all check clean distclean install
