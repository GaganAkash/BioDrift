.PHONY: install dev web lint typecheck test test-cov docker clean

install:
	pip install -e .

dev:
	pip install -e ".[dev,full]"

web:
	pip install -e ".[web]"
	python -m uvicorn webapp.main:app --reload

lint:
	ruff check src tests webapp

fmt:
	ruff format src tests webapp

typecheck:
	mypy src/biodrift

docker:
	docker build -t biodrift .
	docker run --rm -p 8000:8000 -e BIODRIFT_API_TOKEN=dev biodrift

test:
	pytest

test-cov:
	pytest --cov=biodrift --cov-report=term-missing

clean:
	rm -rf build dist *.egg-info .mypy_cache .ruff_cache .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
