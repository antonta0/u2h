BUILD_DIR ?= ./build

GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GIT_COMMIT_HASH := $(shell git log -n 1 --format=%h .)
GIT_DIRTY := $(shell git diff --quiet || echo "-dirty")
GIT_STAMP := $(subst /,_,$(GIT_BRANCH))-$(GIT_COMMIT_HASH)$(GIT_DIRTY)

CONTAINER_CLI ?= podman
CONTAINER_IMAGE_NAME ?= u2h
CONTAINER_IMAGE_VERSION ?= $(GIT_STAMP)
CONTAINER_IMAGE_TAG ?= $(CONTAINER_IMAGE_NAME):$(CONTAINER_IMAGE_VERSION)

.PHONY: all
all: check

.PHONY: check
check:
	cargo clippy

.PHONY: containerimage
containerimage:
	$(CONTAINER_CLI) rmi --force $(CONTAINER_IMAGE_TAG)
	$(CONTAINER_CLI) build --rm -t $(CONTAINER_IMAGE_TAG) .

.PHONY: tarball
tarball: $(BUILD_DIR)/u2h.tar.bz2

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/u2h: $(BUILD_DIR)
	$(CONTAINER_CLI) container create --name extract $(CONTAINER_IMAGE_TAG)
	$(CONTAINER_CLI) container cp extract:/usr/local/bin/u2h $@
	$(CONTAINER_CLI) container rm -f extract
	chmod 0755 $@

$(BUILD_DIR)/README.md $(BUILD_DIR)/LICENSE $(BUILD_DIR)/systemd: $(BUILD_DIR)
	cp -r $(notdir $@) $(dir $@)
	chmod -R u=rwX,g=rX,o=rX $@

$(BUILD_DIR)/SHA256SUMS: $(BUILD_DIR)/u2h
	( cd $(dir $^) ; sha256sum $(notdir $^) > SHA256SUMS )

$(BUILD_DIR)/u2h.tar.bz2: $(BUILD_DIR)/u2h $(BUILD_DIR)/README.md $(BUILD_DIR)/LICENSE $(BUILD_DIR)/systemd $(BUILD_DIR)/SHA256SUMS
	tar -C $(dir $@) --owner=1000 --group=1000 --mtime=$$(date +%F -u --date=@0) -jcf $@ $(patsubst $(abspath $(dir $@))/%,%,$^)

.PHONY: clean
clean:
	rm -r $(BUILD_DIR)
