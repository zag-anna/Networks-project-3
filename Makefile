STARS ?= 3
NODES ?= 4
PY ?= python3

all: build

build:
	$(PY) -m py_compile protocol.py ccs.py cas.py node.py sos.py gen_data.py

data:
	$(PY) gen_data.py --stars $(STARS) --nodes $(NODES) --dir data

run: build data
	$(PY) sos.py --stars $(STARS) --nodes $(NODES)

failover: build data
	$(PY) sos.py --stars $(STARS) --nodes $(NODES) --send-delay 0.15 --kill-ccs-after 1.0

clean:
	rm -rf data output __pycache__

.PHONY: all build data run failover clean
