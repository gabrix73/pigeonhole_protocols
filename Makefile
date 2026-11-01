CRYPTLIB ?= $(HOME)/cryptlib
KATZENQT ?= $(HOME)/katzenqt
GCC ?= $(HOME)/group_chat_client

.PHONY: test vet py-test sync-testdata verify-testdata verify-member

export TMPDIR ?= $(HOME)/scratch/tmp

test:
	mkdir -p $(TMPDIR)
	cd go && go test ./...

vet:
	cd go && go vet ./...

# The Python implementation, under py/.
py-test:
	cd py && python -m pytest -q

verify-member:
	py/scripts/verify-member.sh $(KATZENQT)

sync-testdata:
	CRYPTLIB=$(CRYPTLIB) GCC=$(GCC) scripts/sync-testdata.sh

verify-testdata:
	scripts/verify-testdata.sh

# Cross-checks against katzenqt and Lean's model; OUT holds what they exchange.
OUT ?= $(HOME)/scratch/pigeonhole-conformance
PYTHON ?= $(KATZENQT)/.venv/bin/python
RUNS ?= 200

.PHONY: conformance replay-katzenqt replay-lean diff-katzenqt

conformance: replay-katzenqt replay-lean diff-katzenqt

# Fresh random runs of katzenqt's stateful tests, replayed through the Go member.
replay-katzenqt:
	rm -rf $(OUT)/katzenqt && mkdir -p $(OUT)/katzenqt
	cd $(KATZENQT) && $(PYTHON) tools/groupchat_traces.py $(OUT)/katzenqt 20
	cd go && TRACES=$(OUT)/katzenqt go test -count=1 -run More ./protocols/katzenqt1/member/tracejson/

# Go's scenarios and random runs, replayed through Lean's model.
replay-lean:
	rm -rf $(OUT)/go && mkdir -p $(OUT)/go
	cd go && TRACE_OUT=$(OUT)/go go test -count=1 -run WriteTraces ./protocols/katzenqt1/member/sim/
	cd go && RANDOM_RUNS=$(RUNS) RANDOM_OUT=$(OUT)/go go test -count=1 -run Random ./protocols/katzenqt1/member/sim/
	cd $(CRYPTLIB) && lake exe Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.replay $(OUT)/go

# Go's random scripts, run through katzenqt's simulator.
diff-katzenqt:
	rm -rf $(OUT)/scripts && mkdir -p $(OUT)/scripts
	cd go && RANDOM_RUNS=$(RUNS) RANDOM_OUT=$(OUT)/scripts go test -count=1 -run Random ./protocols/katzenqt1/member/sim/
	cd $(KATZENQT) && PYTHONPATH=src $(PYTHON) $(CURDIR)/scripts/katzenqt_diff.py $(OUT)/scripts

DAEMON ?= @katzenpost

.PHONY: e2e interop

# Two katzenqt1 clients over the client daemon at DAEMON, on a real mixnet.
e2e:
	mkdir -p $(TMPDIR)
	cd go && DAEMON=$(DAEMON) go test -count=1 -timeout 3h -run Live -v ./cmd/katzenqt1/

# katzenqt1 and katzenqt in one group, each way round.
interop:
	scripts/interop-katzenqt.sh host $(DAEMON) $(KATZENQT)
	scripts/interop-katzenqt.sh guest $(DAEMON) $(KATZENQT)

CARGO ?= $(HOME)/.cargo/bin/cargo

.PHONY: rust-test rust-conformance

rust-test:
	mkdir -p $(TMPDIR)
	cd rust && $(CARGO) test --release

.PHONY: examples

examples:
	cd go && go vet ./examples/...
	cd rust && $(CARGO) build --release --examples

# The Rust member against the same traces, and its own random runs against katzenqt and Lean.
rust-conformance: replay-katzenqt
	cd rust && TRACES=$(OUT)/katzenqt $(CARGO) test --release --test katzenqt1_member_replay
	rm -rf $(OUT)/rust && mkdir -p $(OUT)/rust
	cd rust && RANDOM_RUNS=$(RUNS) RANDOM_OUT=$(OUT)/rust $(CARGO) test --release --test katzenqt1_member_sim random_scripts
	cd $(KATZENQT) && PYTHONPATH=src $(PYTHON) $(CURDIR)/scripts/katzenqt_diff.py $(OUT)/rust
	cd $(CRYPTLIB) && lake exe Cryptlib.Protocols.GroupComm.GroupChatKatzenqt1.replay $(OUT)/rust
	cd go && TRACES=$(OUT)/rust go test -count=1 -run More ./protocols/katzenqt1/member/tracejson/
