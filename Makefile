include build/makelib/common.mk
include build/makelib/plugin.mk

# Container image
TAG ?= latest
IMG ?= quay.io/validator-labs/validator-plugin-aws:$(TAG)

# Helm vars
CHART_NAME=validator-plugin-aws

.PHONY: dev
dev:
	devspace dev -n validator

# Static Analysis / CI

chartCrds = chart/validator-plugin-aws/crds/validation.spectrocloud.labs_awsvalidators.yaml

reviewable-ext:
	rm $(chartCrds)
	cp config/crd/bases/validation.spectrocloud.labs_awsvalidators.yaml $(chartCrds)
