all :

check :
	fakeroot python3 -m pytest

clean :
	rm -rf build cert_receive.egg-info dist
	find . -name __pycache__ -type d -prune -exec rm -rf {} \;

install :

.PHONY : all check clean install
