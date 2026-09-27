.PHONY: test docker

test:
	pytest -q

docker:
	docker compose build
