GO ?= go
BINARY ?= mirrorsync
CONFIG ?= config.test.yaml

.PHONY: build test e2e clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w -buildid=" -o $(BINARY) ./cmd/mirrorsync

test:
	$(GO) test ./...

e2e: build
	mkdir -p .e2e/alpine-keys .e2e/repos .e2e/staged
	@if [ ! -s .e2e/alpine-keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub ]; then \
		curl -fsSL https://alpinelinux.org/keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub \
			-o .e2e/alpine-keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub; \
	fi
	./$(BINARY) plan -config $(CONFIG)
	./$(BINARY) sync -config $(CONFIG)
	./$(BINARY) verify -config $(CONFIG)
	./$(BINARY) prune -config $(CONFIG)
	./$(BINARY) verify -config $(CONFIG)

clean:
	rm -f $(BINARY)
