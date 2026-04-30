CC      = gcc
CFLAGS  = -Wall -Wextra -g -I.
LDFLAGS = -pthread

AUTH_BIN    = auth_server/bin/auth_server
TRACKER_BIN = tracker/bin/tracker
PEER_BIN    = peer/bin/peer

AUTH_SRC = auth_server/auth.c auth_server/metadata.c \
           auth_server/common/network.c auth_server/common/utils.c auth_server/common/crypto.c

TRACKER_SRC = tracker/tracker.c \
              tracker/common/network.c tracker/common/utils.c tracker/common/crypto.c

PEER_SRC = peer/main.c peer/network.c peer/download.c peer/upload.c peer/disk.c peer/scheduler.c peer/torrent.c peer/ipc.c \
           peer/common/network.c peer/common/utils.c peer/common/crypto.c

.PHONY: all clean reset auth_server tracker peer ra rt rp1 rp2 rp3 rpa

all: auth_server tracker peer

auth_server:
	mkdir -p auth_server/bin
	$(CC) $(CFLAGS) -o $(AUTH_BIN) $(AUTH_SRC) $(LDFLAGS)
	@echo "  ✓ Built auth_server"

tracker:
	mkdir -p tracker/bin
	$(CC) $(CFLAGS) -o $(TRACKER_BIN) $(TRACKER_SRC) $(LDFLAGS)
	@echo "  ✓ Built tracker"

peer:
	mkdir -p peer/bin
	$(CC) $(CFLAGS) -o $(PEER_BIN) $(PEER_SRC) $(LDFLAGS)
	@for dir in peer/instances/*; do \
		[ -d "$$dir" ] || continue; \
		cp $(PEER_BIN) "$$dir/peer"; \
	done
	@echo "  ✓ Built peer"

clean:
	rm -rf auth_server/bin tracker/bin peer/bin
	@echo "  ✓ Cleaned component binaries"

reset:
	rm -f auth_server/bin/auth_server tracker/bin/tracker peer/bin/peer
	rm -rf auth_server/data/* auth_server/keys/*
	@for d in peer/instances/*; do \
		[ -d "$$d" ] || continue; \
		rm -rf "$$d"/* "$$d"/.[!.]* "$$d"/..?* || true; \
	done
	@echo "  ✓ Reset build outputs and runtime data"

# Run session targets. Each target builds the component first.

ra:
	@echo "Starting auth server (foreground)..."
	./auth_server/bin/auth_server 8080


rt:
	@echo "Starting tracker (foreground)..."
	./tracker/bin/tracker


rp1:
	@echo "Starting peer1 (foreground)..."
	./peer/instances/peer1/peer --port 6001 --peer-dir peer/instances/peer1


rp2:
	@echo "Starting peer2 (foreground)..."
	./peer/instances/peer2/peer --port 6002 --peer-dir peer/instances/peer2


rp3:
	@echo "Starting peer3 (foreground)..."
	./peer/instances/peer3/peer --port 6003 --peer-dir peer/instances/peer3


rpa:
	@echo "Starting peer_admin (foreground)..."
	./peer/instances/peer_admin/peer --port 6010 --peer-dir peer/instances/peer_admin admin

