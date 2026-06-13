BINARY := vulnlist
SOURCE := src/vulnlist.gleam
VERSION := 1.0.0
ARCH := darwin

ifeq ($(shell id -u), 0)
    PREFIX := /usr/local
else
    PREFIX := $(HOME)/.local
endif
BINDIR := $(PREFIX)/bin

.PHONY: build test install dist clean

build: $(BINARY)-darwin $(BINARY)-linux-x64 $(BINARY)-linux-arm64
	
$(BINARY)-darwin: $(SOURCE) manifest.toml
	gleam build
	bun build --compile --target bun-darwin-arm64 --minify --bytecode --outfile=$@ entry.js

$(BINARY)-linux-x64: $(SOURCE) manifest.toml
	gleam build
	bun build --compile --target bun-linux-x64 --minify --bytecode --outfile=$@ entry.js

$(BINARY)-linux-arm64: $(SOURCE) manifest.toml
	gleam build
	bun build --compile --target bun-linux-arm64 --minify --bytecode --outfile=$@ entry.js

test:
	gleam test

install: $(BINARY)-$(ARCH)
	@echo "Installing $(BINARY)-$(ARCH) to $(BINDIR)/$(BINARY)..."
	mkdir -p $(BINDIR)
	cp $(BINARY)-$(ARCH) $(BINDIR)/$(BINARY)
	chmod 755 $(BINDIR)/$(BINARY)

dist: $(BINARY)-$(VERSION).tgz

$(BINARY)-$(VERSION).tgz: $(SOURCE) package.json bin/cli.js
	bun run build:dist
	bun pm pack

clean:
	-rm -f $(BINARY)-darwin
	-rm -f $(BINARY)-linux-x64
	-rm -f $(BINARY)-linux-arm64
	-rm -rf dist
	-rm -rf build
	-rm -rf ort-result
	-rm -f $(BINARY)-$(VERSION).tgz
