PREFIX=/usr/local
BINDIR=$(PREFIX)/bin

all:
	@echo "Run \"sudo make install\" to install netfoot"

clean:
	make -C tests/ clean
	rm -f *.pyc
	rm -rf __pycache__

install:
	install -m 0755 netfoot.py $(BINDIR)/netfoot
	install -m 0755 netfoot_remote.sh $(BINDIR)/netfoot_remote
	install -m 0755 netcred.sh $(BINDIR)/netcred

uninstall:
	rm -f $(BINDIR)/netfoot
	rm -f $(BINDIR)/netfoot_remote
	rm -f $(BINDIR)/netcred

tests:
	make -C tests/

.PHONY: tests
