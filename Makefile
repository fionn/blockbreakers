SRC = aes.py constants.py square.py
TEST = test.py

tags: $(SRC) $(TEST)
	@ctags --languages=python --python-kinds=-i $(SRC) $(TEST)

.PHONY: test
test:
	@python -m unittest

coverage: $(SRC) $(TEST)
	@coverage run --source=. --branch --concurrency=thread test.py
	@coverage report -m
	@coverage html -d ./coverage
	@coverage erase

.PHONY: lint
lint:
	@pylint -f colorized $(SRC) $(TEST)

.PHONY: typecheck
typecheck:
	@mypy $(SRC) $(TEST)

.PHONY: clean
clean:
	@$(RM) -r coverage
	@$(RM) -r .mypy_cache
	@$(RM) -r __pycache__
	@$(RM) tags
