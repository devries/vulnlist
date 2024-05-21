BINARY := vulnlist
SOURCE := src/vulnlist.gleam

.PHONY: build test

build: $(BINARY)
	
$(BINARY): $(SOURCE) manifest.toml
	gleam run -m gleescript

test:
	gleam test
