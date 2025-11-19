all :

check :
	fakeroot python3 -m pytest

clean :
	find . -name __pycache__ -type d -prune -exec rm -rf {} \;

install :

.PHONY : all check clean install
