all: compile

HOSTNAME ?= $(shell hostname)
CERTDIR   = priv/certs

compile: certs
	rebar compile

cert: certs
certs:
	@mkdir -p  $(CERTDIR)
	@chmod 700 $(CERTDIR)
	@# Create Certificate Authority in PEM format, and in DER format (for Microsoft and Mono)
	@if [ ! -f $(CERTDIR)/cacert.pem ]; then \
        echo 01 > $(CERTDIR)/serial; \
        touch     $(CERTDIR)/index.txt; \
        openssl req -x509 -config priv/openssl.cnf -newkey rsa:2048 -days 365 \
                -out certs/cacert.pem -outform PEM -subj /CN=MyTestCA/ -nodes; \
	    openssl x509 -in certs/cacert.pem -out certs/cacert.cer -outform DER; \
        echo "  {cacertfile, \"certs/cacert.pem\"}"; \
    fi
	@#------- server certificate ---------
	@if [ ! -f $(CERTDIR)/server/req.pem ]; then \
        echo "Generating server certificate for host: $(HOSTNAME)"; \
        mkdir -p $(CERTDIR)/server; \
        openssl genrsa -out $(CERTDIR)/server/key.pem 2048; \
        openssl req -new -key $(CERTDIR)/server/key.pem -out $(CERTDIR)/server/req.pem -outform PEM \
                -subj /CN=$(HOSTNAME)/O=server/ -nodes; \
        openssl ca -config priv/openssl.cnf -in $(CERTDIR)/server/req.pem -out \
            $(CERTDIR)/server/cert.pem -notext -batch -extensions server_ca_extensions; \
        echo "  {certfile,   \"$(CERTDIR)/server/cert.pem\"}"; \
    fi
	@#------- client certificate ---------
	@if [ ! -f $(CERTDIR)/client/req.pem ]; then \
        echo "generating client certificate for host: $(HOSTNAME)"; \
        mkdir -p $(CERTDIR)/client; \
        openssl genrsa -out $(CERTDIR)/client/key.pem 2048; \
        openssl req -new -key $(CERTDIR)/client/key.pem -out $(CERTDIR)/client/req.pem -outform PEM \
                -subj /CN=$(HOSTNAME)/O=client/ -nodes; \
        openssl ca -config priv/openssl.cnf -in $(CERTDIR)/client/req.pem -out \
            $(CERTDIR)/client/cert.pem -notext -batch -extensions client_ca_extensions; \
        echo "  {keyfile,    \"$(CERTDIR)/server/key.pem\"}"; \
    fi
	@rm -f $(CERTDIR)/*.old

.PHONY: cert certs
