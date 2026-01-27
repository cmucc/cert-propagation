PYTHON = python3

all :

check :
	fakeroot $(PYTHON) -m pytest

clean :
	rm -rf build cert_receive.egg-info dist
	find . -path ./.tox -prune -o \
	       -name __pycache__ -type d -prune -exec rm -rf {} \;

distclean : clean
	rm -rf .tox

install :

.PHONY : all check clean distclean install
