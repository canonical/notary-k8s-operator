.PHONY: check-shared-modules

SHARED_MODULES := notary.py s3.py utils.py grafana_dashboards/notary.json

check-shared-modules:
	@for module in $(SHARED_MODULES); do \
		cmp --silent "k8s/src/$$module" "machine/src/$$module" || { \
			echo "Shared module differs: $$module" >&2; \
			exit 1; \
		}; \
	done