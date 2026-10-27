.PHONY: up down logs build test lint fixtures evaluate

up:          ## start redis, api, worker and ui (UI :8501, API :8000)
	docker compose up -d --build

down:        ## stop everything (volumes are kept)
	docker compose down

logs:
	docker compose logs -f

build:
	docker compose build

test:        ## run the test suite (network is mocked)
	pytest -q

lint:
	ruff check .

fixtures:    ## regenerate the synthetic test emails
	python scripts/make_fixtures.py

evaluate:    ## evaluate on the fixtures without network
	python scripts/evaluate.py tests/fixtures --labels tests/fixtures/eval_labels.csv --no-network
