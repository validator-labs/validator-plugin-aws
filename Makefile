include build/makelib/common.mk
include build/makelib/plugin.mk

# Image URL to use all building/pushing image targets
IMG ?= quay.io/validator-labs/validator-plugin-aws:latest

# Helm vars
CHART_NAME=validator-plugin-aws

.PHONY: dev
dev:
	devspace dev -n validator