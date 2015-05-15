all: compile

HOSTNAME ?= $(shell hostname)

compile: certs
	rebar compile

cert: certs
certs:
	@mkdir -p  certs/private
	@chmod 700 certs/private
	@# Create Certificate Authority in PEM format, and in DER format (for Microsoft and Mono)
	@if [ ! -f certs/cacert.pem ]; then \
        echo 01 > certs/serial; \
        touch     certs/index.txt; \
        openssl req -x509 -config priv/openssl.cnf -newkey rsa:2048 -days 365 \
                -out certs/cacert.pem -outform PEM -subj /CN=MyTestCA/ -nodes; \
	    openssl x509 -in certs/cacert.pem -out certs/cacert.cer -outform DER; \
        echo "  {cacertfile, \"certs/cacert.pem\"}"; \
    fi
	@#------- server certificate ---------
	@if [ ! -f certs/server/req.pem ]; then \
        echo "Generating server certificate for host: $(HOSTNAME)"; \
        mkdir -p certs/server; \
        openssl genrsa -out certs/server/key.pem 2048; \
        openssl req -new -key certs/server/key.pem -out certs/server/req.pem -outform PEM \
                -subj /CN=$(HOSTNAME)/O=server/ -nodes; \
        openssl ca -config priv/openssl.cnf -in certs/server/req.pem -out \
            certs/server/cert.pem -notext -batch -extensions server_ca_extensions; \
        echo "  {certfile,   \"certs/server/cert.pem\"}"; \
    fi
	@#------- client certificate ---------
	@if [ ! -f certs/client/req.pem ]; then \
        echo "generating client certificate for host: $(HOSTNAME)"; \
        mkdir -p certs/client; \
        openssl genrsa -out certs/client/key.pem 2048; \
        openssl req -new -key certs/client/key.pem -out certs/client/req.pem -outform PEM \
                -subj /CN=$(HOSTNAME)/O=client/ -nodes; \
        openssl ca -config priv/openssl.cnf -in certs/client/req.pem -out \
            certs/client/cert.pem -notext -batch -extensions client_ca_extensions; \
        echo "  {keyfile,    \"certs/server/key.pem\"}"; \
    fi
	@rm -f certs/*.old

.PHONY: cert certs
