.PHONY: install run test lint clean

install:
	pip3 install -r requirements.txt --break-system-packages

run:
	python3 analyzer.py --help

test:
	python3 -m pytest tests/ -v --tb=short

test-cov:
	python3 -m pytest tests/ -v --tb=short --co -q

lint:
	python3 -m py_compile analyzer.py log_analyzer/*.py && echo "Syntax OK"

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
	find . -name "*.pyc" -delete 2>/dev/null; \
	rm -f /tmp/test_*.log; \
	echo "Clean done"
