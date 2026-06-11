BINARY := vulnlist
SOURCE := src/vulnlist.gleam

ifeq ($(shell id -u), 0)
    PREFIX := /usr/local
else
    PREFIX := $(HOME)/.local
endif
BINDIR := $(PREFIX)/bin

.PHONY: build test

build: $(BINARY)
	
$(BINARY): $(SOURCE) manifest.toml
	gleam build
	bun build --compile --outfile=vulnlist build/dev/javascript/vulnlist/vulnlist.mjs --footer="main();"

test:
	gleam test

install: $(BINARY)
	@echo "Installing $(BINARY) to $(BINDIR)..."
	mkdir -p $(BINDIR)
	cp $(BINARY) $(BINDIR)/
	chmod 755 $(BINDIR)/$(BINARY)
