# SPDX-License-Identifier: GPL-2.0
#
# TLC over the TLA+ mirror of the work-conservation model (Lachesis.tla).
# `make` runs every configuration: the positive ones must pass and the
# negative ones, each a weakened policy, must report a violation. TLA+
# tools are fetched into $(BUILD_DIR)/tla on first use -- 1.7.4 is the
# last release that runs on Java 8 -- and TLC's state files go there too,
# so nothing lands in the source tree. Each run uses every core, so the
# configurations run one at a time.

BUILD_DIR ?= $(abspath ../../build)
TLA_DIR := $(BUILD_DIR)/tla
JAR := $(TLA_DIR)/tla2tools.jar
TLA_VERSION ?= v1.7.4
TLA_URL := https://github.com/tlaplus/tlaplus/releases/download/$(TLA_VERSION)/tla2tools.jar
JAVA ?= java
WORKERS ?= auto
TLC = $(JAVA) -XX:+UseParallelGC -cp $(JAR) tlc2.TLC -workers $(WORKERS) -cleanup

# tol_first_only is a weakened policy the design tolerates: a steal that
# gives up after its first candidate is caught by the idle-side count check,
# so it must pass. pos_3x2 is the long one, hours on this host.
POSITIVE := pos_2x2 pos_2x3 tol_first_only pos_2x2_live pos_3x2
NEGATIVE := neg_no_steal neg_no_enq_kick neg_no_idle_kick neg_local_select

.NOTPARALLEL:
.PHONY: all fetch clean

all: $(POSITIVE:%=$(TLA_DIR)/%.ok) $(NEGATIVE:%=$(TLA_DIR)/%.ok)
	@echo "tlc: every configuration behaved as expected"

fetch: $(JAR)

$(JAR):
	@mkdir -p $(TLA_DIR)
	curl -fsSL -o $@ $(TLA_URL)

# A positive configuration passes or the target fails with the log's tail.
define positive_rule
$(TLA_DIR)/$(1)_%.ok: $(1)_%.cfg Lachesis.tla $(JAR)
	@mkdir -p $(TLA_DIR)/states
	@echo "tlc $(1)_$$*"
	@$(TLC) -metadir $(TLA_DIR)/states/$(1)_$$* -config $$< Lachesis.tla \
		> $(TLA_DIR)/$(1)_$$*.log 2>&1 || { tail -40 $(TLA_DIR)/$(1)_$$*.log; exit 1; }
	@grep -q 'No error has been found' $(TLA_DIR)/$(1)_$$*.log
	@grep -E 'distinct states found|Finished in' $(TLA_DIR)/$(1)_$$*.log | tail -2
	@touch $$@
endef
$(eval $(call positive_rule,pos))
$(eval $(call positive_rule,tol))

# A negative configuration must violate CWC (or, for the steal-less
# variant, the kick-resolution property); passing is the failure.
$(TLA_DIR)/neg_%.ok: neg_%.cfg Lachesis.tla $(JAR)
	@mkdir -p $(TLA_DIR)/states
	@echo "tlc neg_$*"
	@$(TLC) -metadir $(TLA_DIR)/states/neg_$* -config $< Lachesis.tla \
		> $(TLA_DIR)/neg_$*.log 2>&1 || true
	@grep -qE 'Invariant CWC is violated|Temporal properties were violated' \
		$(TLA_DIR)/neg_$*.log || \
		{ echo "neg_$*: expected a violation, got none"; \
		  tail -20 $(TLA_DIR)/neg_$*.log; exit 1; }
	@grep -oE 'Invariant CWC is violated|Temporal properties were violated' \
		$(TLA_DIR)/neg_$*.log | head -1
	@touch $@

clean:
	rm -rf $(TLA_DIR)/*.ok $(TLA_DIR)/*.log $(TLA_DIR)/states
