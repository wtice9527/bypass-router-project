PYTHON ?= .venv/bin/python
ROUTERCTL ?= .venv/bin/routerctl
VERSION := $(shell cat VERSION)

.PHONY: setup test validate generate scan release clean

setup:
	python3 -m venv .venv
	.venv/bin/pip install -e '.[test]'

test:
	$(PYTHON) -m pytest -q

validate:
	$(ROUTERCTL) validate -c config.example.json

scan:
	$(PYTHON) scripts/scan-secrets.py
	$(PYTHON) scripts/verify-governance.py

generate:
	$(ROUTERCTL) generate -c config.example.json -o build/rootfs

release: test validate scan
	rm -rf dist/stage
	mkdir -p dist/stage/debian-side-router-$(VERSION) release
	tar --exclude='./.git' --exclude='./.venv' --exclude='./build' --exclude='./dist' \
	    --exclude='./release' --exclude='./.pytest_cache' --exclude='__pycache__' \
	    --exclude='./config.json' --exclude='./secrets.json' --exclude='./secrets.*.json' \
	    --exclude='./.env' --exclude='./.env.*' --exclude='*.bak' --exclude='*.backup' \
	    -cf - . | tar -C dist/stage/debian-side-router-$(VERSION) -xf -
	tar -C dist/stage -czf release/debian-side-router-$(VERSION).tar.gz debian-side-router-$(VERSION)
	sha256sum release/debian-side-router-$(VERSION).tar.gz > release/debian-side-router-$(VERSION).tar.gz.sha256

clean:
	rm -rf build dist release/*.tar.gz release/*.sha256 .pytest_cache
