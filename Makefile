SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
KKD_DIR ?= $(ROOT_DIR)/dep/kkd

GIT ?= git
KKD_REBASE_REMOTE ?= origin
KKD_REBASE_BRANCH ?= main
KKD_REBASE_URL ?=

.PHONY: help \
	kkd-sync all-sync sync \
	kkd-rebase all-rebase rebase

.NOTPARALLEL: all-sync

define sync_repo
	@if [[ ! -e "$(1)/.git" ]]; then \
		echo "$(2) checkout is missing at $(1); run 'git submodule update --init'" >&2; \
		exit 1; \
	fi; \
	branch="$$($(GIT) -C "$(1)" symbolic-ref --quiet --short HEAD)" || { \
		echo "$(2) is on a detached HEAD; attach its working branch first" >&2; \
		exit 1; \
	}; \
	upstream="$$($(GIT) -C "$(1)" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null)" || { \
		echo "$(2) branch '$$branch' has no tracking branch" >&2; \
		exit 1; \
	}; \
	if ! $(GIT) -C "$(1)" diff --quiet || \
	   ! $(GIT) -C "$(1)" diff --cached --quiet; then \
		echo "$(2) has tracked or staged changes; commit or stash them before syncing" >&2; \
		exit 1; \
	fi; \
	echo "Syncing $(2) $$branch onto $$upstream"; \
	$(GIT) -c commit.gpgsign=false -C "$(1)" pull --rebase --no-autostash
endef

# $(call rebase_repo,<dir>,<name>,<remote>,<branch>,<url-if-remote-missing>)
define rebase_repo
	@if [[ ! -e "$(1)/.git" ]]; then \
		echo "$(2) checkout is missing at $(1); run 'git submodule update --init'" >&2; \
		exit 1; \
	fi; \
	branch="$$($(GIT) -C "$(1)" symbolic-ref --quiet --short HEAD)" || { \
		echo "$(2) is on a detached HEAD; attach its working branch first" >&2; \
		exit 1; \
	}; \
	if ! $(GIT) -C "$(1)" diff --quiet || \
	   ! $(GIT) -C "$(1)" diff --cached --quiet; then \
		echo "$(2) has tracked or staged changes; commit or stash them before rebasing" >&2; \
		exit 1; \
	fi; \
	if ! $(GIT) -C "$(1)" remote get-url "$(3)" >/dev/null 2>&1; then \
		if [[ -n "$(5)" ]]; then \
			echo "Adding $(2) remote $(3) -> $(5)"; \
			$(GIT) -C "$(1)" remote add "$(3)" "$(5)"; \
		else \
			echo "$(2) has no remote named '$(3)'" >&2; \
			exit 1; \
		fi; \
	fi; \
	$(GIT) -C "$(1)" fetch "$(3)" "$(4)"; \
	echo "Rebasing $(2) $$branch onto $(3)/$(4)"; \
	$(GIT) -c commit.gpgsign=false -C "$(1)" rebase "$(3)/$(4)"; \
	push_remote="$$($(GIT) -C "$(1)" config --get "branch.$$branch.remote" || echo origin)"; \
	local_sha="$$($(GIT) -C "$(1)" rev-parse "refs/heads/$$branch")"; \
	remote_sha="$$($(GIT) -C "$(1)" rev-parse --quiet --verify "refs/remotes/$$push_remote/$$branch" || echo unpushed)"; \
	if [[ "$$local_sha" == "$$remote_sha" ]]; then \
		echo "$(2) $$branch already up to date on $$push_remote"; \
	else \
		echo "Force-pushing $(2) $$branch to $$push_remote"; \
		$(GIT) -C "$(1)" push --force-with-lease "$$push_remote" "$$branch"; \
	fi
endef

help:
	@printf '%s\n' \
		'Targets:' \
		'  kkd-sync      Pull and rebase kkd onto its tracking branch' \
		'  all-sync      Sync every dep' \
		'  sync          Alias for all-sync' \
		'  kkd-rebase    Rebase kkd onto origin/main and push' \
		'  all-rebase    Rebase+push every dep; keeps going past failures' \
		'  rebase        Alias for all-rebase' \
		'' \
		'Useful overrides:' \
		'  <DEP>_REBASE_REMOTE/_BRANCH/_URL with DEP=KKD'

kkd-sync:
	$(call sync_repo,$(KKD_DIR),kkd)

all-sync: kkd-sync

sync: all-sync

kkd-rebase:
	$(call rebase_repo,$(KKD_DIR),kkd,$(KKD_REBASE_REMOTE),$(KKD_REBASE_BRANCH),$(KKD_REBASE_URL))

all-rebase:
	@failed=""; \
	for target in kkd-rebase; do \
		$(MAKE) "$$target" || failed="$$failed $$target"; \
	done; \
	if [[ -n "$$failed" ]]; then \
		echo "rebase failed for:$$failed" >&2; \
		echo "conflicted repos are left mid-rebase; resolve and 'git rebase --continue'" >&2; \
		echo "(or 'git rebase --abort'), then re-run 'make rebase' to finish and push" >&2; \
		exit 1; \
	fi

rebase: all-rebase
