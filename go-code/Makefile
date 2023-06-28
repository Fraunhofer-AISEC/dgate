ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
SGX_SIGNER_KEY ?= ~/.config/gramine/enclave-key.pem

# This Makefile is targeted towards the client. The server is assumed to run outside SGX.

.PHONY: all
all: go client.manifest client.manifest.sgx client.sig client.token

.PHONY: go
go:
	go build .

client.manifest: client.manifest.template
	gramine-manifest \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dentrypoint=time_server \
		$< > $@

client.manifest.sgx: client.manifest
	@test -s $(SGX_SIGNER_KEY) || \
	    { echo "SGX signer private key was not found, please specify SGX_SIGNER_KEY!"; exit 1; }
	gramine-sgx-sign \
		--key $(SGX_SIGNER_KEY) \
		--manifest $< \
		--output $@

client.sig: client.manifest.sgx

client.token: client.sig
	gramine-sgx-get-token --output $@ --sig $<

.PHONY: clean
clean:
	$(RM) time_server
	$(RM) *.token *.sig *.manifest.sgx *.manifest
