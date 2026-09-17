.PHONY: install test run evaluate

install:
	python -m pip install -e ".[dev]"

test:
	python -m pytest

run:
	uvicorn queryguard.api:app --reload

evaluate:
	python -c "from queryguard.evaluation import evaluate; print(evaluate())"
