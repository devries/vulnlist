BINARY := vulnlist
SOURCE := src/vulnlist.gleam

.PHONY: build test

build: $(BINARY)
	
$(BINARY): $(SOURCE) manifest.toml
	gleam export escript

test:
	gleam test
