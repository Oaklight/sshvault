.DEFAULT_GOAL := help

PYTHON ?= python3

.PHONY: help
help:
	@echo "Targets: lint fmt test build push clean"

.PHONY: lint
lint:
	ruff check src/ tests/
	ruff format --check src/ tests/
	ty check

.PHONY: fmt
fmt:
	ruff check --fix src/ tests/
	ruff format src/ tests/

.PHONY: test
test:
	pytest tests/ -v

.PHONY: build
build: clean
	$(PYTHON) -m build
	twine check dist/*

.PHONY: push
push:
	twine upload dist/*

.PHONY: clean
clean:
	rm -rf dist build *.egg-info src/*.egg-info
