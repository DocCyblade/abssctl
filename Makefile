PYTHON ?= python3.11
DEV_VENV ?= .venv
BUILD_VENV ?= .venv-build
TEST_VENV ?= .venv-test
PIP_TEST_VENV ?= /tmp/python-tests/abssctl/.venv-test
PACKAGE_NAME ?= abssctl
VERSION ?= 0.1.0a1

.DEFAULT_GOAL := help
USER_SHELL := $(shell echo $$SHELL)

## help: Show this help message (default target)
.PHONY: help
help:
	@awk 'BEGIN {FS=":"} \
	/^## / {line=substr($$0,4); pos=index(line,": "); desc=(pos>0)?substr(line,pos+2):line; next} \
	/^\.PHONY/ {next} \
	/^[a-zA-Z_.-]+:/ {if (desc){printf "%-20s %s\n", $$1, desc; desc=""}}' $(MAKEFILE_LIST)

$(DEV_VENV)/.installed: pyproject.toml Makefile
	@if [ ! -d "$(DEV_VENV)" ]; then \
		echo "[dev] Creating virtual environment $(DEV_VENV)"; \
		$(PYTHON) -m venv $(DEV_VENV) --prompt dev; \
	else \
		echo "[dev] Reusing existing virtual environment $(DEV_VENV)"; \
	fi
	$(DEV_VENV)/bin/python -m pip install --upgrade pip
	$(DEV_VENV)/bin/python -m pip install -e .[dev]
	touch $@

$(BUILD_VENV)/.installed: pyproject.toml Makefile
	@echo "[build] Creating virtual environment $(BUILD_VENV)"
	rm -rf $(BUILD_VENV)
	$(PYTHON) -m venv $(BUILD_VENV) --prompt build
	$(BUILD_VENV)/bin/python -m pip install --upgrade pip
	$(BUILD_VENV)/bin/python -m pip install build twine
	touch $@

$(TEST_VENV)/.installed: pyproject.toml Makefile
	@echo "[test] Creating virtual environment $(TEST_VENV)"
	rm -rf $(TEST_VENV)
	$(PYTHON) -m venv $(TEST_VENV) --prompt test
	$(TEST_VENV)/bin/python -m pip install --upgrade pip
	$(TEST_VENV)/bin/python -m pip install -e .[dev]
	touch $@

$(PIP_TEST_VENV)/.installed: Makefile
	@echo "[pkg-test] Creating virtual environment $(PIP_TEST_VENV)"
	rm -rf $(PIP_TEST_VENV)
	$(PYTHON) -m venv $(PIP_TEST_VENV) --prompt pkgtest
	$(PIP_TEST_VENV)/bin/python -m pip install --upgrade pip
	touch $@

.PHONY: ensure-dev-venv
ensure-dev-venv: $(DEV_VENV)/.installed

.PHONY: ensure-test-venv
ensure-test-venv: $(TEST_VENV)/.installed

.PHONY: ensure-build-venv
ensure-build-venv: $(BUILD_VENV)/.installed

## Quick Tests on dev: Run Ruff/mypy/pytest
.PHONY: quick-tests
quick-tests: $(DEV_VENV)/.installed
	$(DEV_VENV)/bin/python -m ruff check src tests tools
	$(DEV_VENV)/bin/python -m mypy src
	$(DEV_VENV)/bin/python -m pytest -m "not slow"

.PHONY: coverage
coverage: $(DEV_VENV)/.installed
	$(DEV_VENV)/bin/python -m pytest --cov=src/abssctl --cov-report=term-missing

## lint: Run Ruff via .venv-test (test env)
.PHONY: lint
lint: $(TEST_VENV)/.installed
	$(TEST_VENV)/bin/python -m ruff check src tests tools

## type: Run mypy type checks via test venv
.PHONY: type
type: $(TEST_VENV)/.installed
	$(TEST_VENV)/bin/python -m mypy src

## test: Run pytest suite via test venv
.PHONY: test
test: $(TEST_VENV)/.installed
	$(TEST_VENV)/bin/python -m pytest

## docs: Build Sphinx docs via .venv (dev env)
.PHONY: docs
docs: $(DEV_VENV)/.installed
	rm -rf docs/_build/html
	$(DEV_VENV)/bin/python -m sphinx.cmd.build -b html docs/source docs/_build/html

## build: Build distributions via .venv-build (build env)
.PHONY: build
build: $(BUILD_VENV)/.installed
	rm -rf dist build *.egg-info
	$(BUILD_VENV)/bin/python -m build

## dist: Lint, type-check, test, then build artifacts
.PHONY: dist
dist: lint type test build

## smoke: Install the wheel from dist/ inside build venv and print version
.PHONY: smoke
smoke: $(BUILD_VENV)/.installed build
	$(BUILD_VENV)/bin/python -m pip install --force-reinstall dist/$(PACKAGE_NAME)-$(VERSION)-*.whl
	$(BUILD_VENV)/bin/python -c "import $(PACKAGE_NAME); print($(PACKAGE_NAME).__version__)"

## publish-test: Upload dist/ artifacts to TestPyPI via build venv
.PHONY: publish-test
publish-test: $(BUILD_VENV)/.installed dist
	$(BUILD_VENV)/bin/python -m twine upload --repository testpypi dist/*

## publish: Upload dist/ artifacts to PyPI via build venv
.PHONY: publish
publish: $(BUILD_VENV)/.installed dist
	$(BUILD_VENV)/bin/python -m twine upload dist/*

install-package: $(PIP_TEST_VENV)/.installed
	$(PIP_TEST_VENV)/bin/python -m pip install --no-cache-dir \
		--index-url $(INDEX_URL) \
		$(if $(EXTRA_INDEX_URL),--extra-index-url $(EXTRA_INDEX_URL)) \
		$(PACKAGE_NAME)==$(VERSION)

## install-test: Install package from TestPyPI into /tmp venv via pkg-test venv
.PHONY: install-test
install-test: INDEX_URL=https://test.pypi.org/simple/
install-test: EXTRA_INDEX_URL=https://pypi.org/simple
install-test: install-package

## install-prod: Install package from PyPI into /tmp venv via pkg-test venv
.PHONY: install-prod
install-prod: INDEX_URL=https://pypi.org/simple
install-prod: EXTRA_INDEX_URL=
install-prod: install-package

## clean: Remove build artifacts
.PHONY: clean
clean:
	rm -rf dist build *.egg-info docs/_build

## clean-cache: Remove Python and tooling caches
.PHONY: clean-cache
clean-cache:
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	find . -type f -name "*.py[co]" -delete
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov

## clean-venv-dev: Remove managed dev virtual environment
.PHONY: clean-venv-dev
clean-venv-dev:
	rm -rf $(DEV_VENV)

## clean-venv-build: Remove managed build virtual environment
.PHONY: clean-venv-build
clean-venv-build:
	rm -rf $(BUILD_VENV)

## clean-venv-test: Remove managed test virtual environment
.PHONY: clean-venv-test
clean-venv-test:
	rm -rf $(TEST_VENV)

## clean-venv-piptest: Remove managed piptest virtual environment
.PHONY: clean-venv-piptest
clean-venv-piptest:
	rm -rf $(PIP_TEST_VENV)

## clean-venv: Remove all managed virtual environments
.PHONY: clean-venv
clean-venv:
	rm -rf $(DEV_VENV) $(BUILD_VENV) $(TEST_VENV) $(PIP_TEST_VENV)


## clean-all: Remove build artifacts, caches, and virtual environments
.PHONY: clean-all
clean-all: clean clean-cache clean-venv
