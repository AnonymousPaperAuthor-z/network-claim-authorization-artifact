.PHONY: check test metrics benchmark training release

check:
	python scripts/run_all.py

test:
	python -m unittest discover -s tests -v

metrics:
	python scripts/reproduce_paper_metrics.py

benchmark:
	python scripts/verify_benchmark.py

training:
	python scripts/verify_training_data.py

release:
	python scripts/build_release_manifest.py
	python scripts/verify_release.py
