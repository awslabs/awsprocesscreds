TESTS=tests/unit tests/functional
MODULE=awsprocesscreds/

check:
	###### FLAKE8 #####
	# No unused imports, no undefined vars
	flake8 --ignore=E731,W503 --exclude compat.py --max-complexity 10 $(MODULE)
	flake8 tests/unit/ tests/functional/ tests/integration/
	# Proper docstring conventions according to pep257
	pydocstyle --add-ignore=D100,D101,D102,D103,D104,D105,D204,D301 $(MODULE)

pylint:
	pylint --rcfile .pylintrc $(MODULE)

test:
	py.test -v $(TESTS)

coverage:
	py.test --cov $(MODULE) --cov-report term-missing $(TESTS)

htmlcov:
	py.test --cov $(MODULE) --cov-report html $(TESTS)
	rm -rf /tmp/htmlcov && mv htmlcov /tmp/
	open /tmp/htmlcov/index.html

prcheck: check pylint test
