RPC = rpcgen
CC = g++
CFLAGS = -lnsl -Wall -g -Wno-unused-variable -Wno-return-type
PROGRAM = rpc_tema
SRC_SERVER = $(PROGRAM)_svc.h $(PROGRAM)_xdr.c
SRC_CLIENT = $(PROGRAM)_clnt.c $(PROGRAM)_xdr.c

.PHONY: build clean

build: rpc server client

server: $(PROGRAM)_server.cpp $(SRC_SERVER)
	$(CC) -o server $^ $(CFLAGS)

client: $(PROGRAM)_client.cpp $(SRC_CLIENT)
	$(CC) -o client $^ $(CFLAGS)

rpc:
	$(RPC) -C $(PROGRAM).x
	rm -f $(PROGRAM)_svc.c

$(PROGRAM)_svc.h: $(PROGRAM).x
	$(RPC) -m $^ > $(PROGRAM)_svc.h

clean:
	rm -f client server $(PROGRAM)_svc.h $(PROGRAM)_xdr.c $(PROGRAM)_clnt.c $(PROGRAM).h