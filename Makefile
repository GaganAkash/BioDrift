.PHONY: install dev lint typecheck test fmt clean

install:
	pip install -e .

dev:
	pip install -e ".[dev,full]"

lint:
	ruff check src tests

fmt:
	ruff format src tests

typecheck:
	mypy src/biodrift

test:
	pytest

test-cov:
	pytest --cov=biodrift --cov-report=term-missing

clean:
	rm -rf build dist *.egg-info .mypy_cache .ruff_cache .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
