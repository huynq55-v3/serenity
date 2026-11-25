TARGET_MUSL := x86_64-unknown-linux-musl
BUILD_DIR   := build
KERNEL      ?= $(shell if test -r $(BUILD_DIR)/rootfs-stage/boot/vmlinuz-serenity; then echo $(BUILD_DIR)/rootfs-stage/boot/vmlinuz-serenity; elif test -r $(BUILD_DIR)/bzImage; then echo $(BUILD_DIR)/bzImage; else echo /boot/vmlinuz_rust; fi)
INITRAMFS   := $(BUILD_DIR)/initramfs.cpio.gz
DISK_IMG    := $(BUILD_DIR)/disk.img
DISK_GUI    := $(BUILD_DIR)/disk-gui.img
QEMU        := qemu-system-x86_64
QEMU_MEM    ?= 512M
QEMU_ACCEL  := $(shell test -r /dev/kvm -a -w /dev/kvm && echo "-enable-kvm -cpu host")

.PHONY: help check-deps init spkg compositor shell-ui capture nushell coreutils kernel disk initramfs packages run run-gui run-compositor run-desktop run-initramfs smoke-test clean

help:
	@echo "Serenity Linux Build Targets:"
	@echo "  make check-deps     - Verify host tools and Rust musl target"
	@echo "  make init           - Build Rust PID 1 (x86_64-unknown-linux-musl)"
	@echo "  make spkg           - Build Rust Package Manager spkg (x86_64-unknown-linux-musl)"
	@echo "  make compositor     - Build Serenity Wayland Compositor (Smithay 0.7)"
	@echo "  make shell-ui       - Build Serenity Login & Wi-Fi GUI Shell (iced)"
	@echo "  make capture        - Build Serenity Screenshot & Screen Recorder (Ubuntu-style HUD)"
	@echo "  make nushell        - Download static musl Nushell binary"
	@echo "  make coreutils      - Download static musl uutils/coreutils binary"
	@echo "  make kernel         - Download & compile minimal Linux Kernel -> build/bzImage"
	@echo "  make disk           - Build persistent ext4 disk image -> build/disk.img"
	@echo "  make initramfs      - Build RAM-only initramfs -> build/initramfs.cpio.gz"
	@echo "  make packages       - Build .tar.zst packages + index.json locally"
	@echo "  make run            - Boot Serenity in QEMU (serial console)"
	@echo "  make run-gui        - Boot Serenity in QEMU with VirGL GPU window (GTK)"
	@echo "  make run-compositor - Launch Smithay Wayland compositor on host desktop"
	@echo "  make run-desktop    - Launch Smithay + Serenity Login/Wi-Fi GUI on host desktop"
	@echo "  make run-initramfs  - Boot Serenity in QEMU from RAM-only initramfs"
	@echo "  make smoke-test     - Automated QEMU boot + coreutils + net + poweroff test"
	@echo "  make clean          - Remove build artifacts"

check-deps:
	@echo "==> Checking Rust & musl target..."
	@rustc --version
	@rustup target list --installed | grep -q "$(TARGET_MUSL)" || (echo "Run: rustup target add $(TARGET_MUSL)" && exit 1)
	@echo "==> Checking QEMU & rootfs tools..."
	@for cmd in $(QEMU) cpio gzip curl tar /usr/sbin/mke2fs; do \
		command -v $$cmd >/dev/null || (echo "Missing: $$cmd" && exit 1); \
	done
	@echo "==> Checking Linux Kernel build tools..."
	@missing=""; \
	for cmd in gcc make flex bison bc xz; do \
		command -v $$cmd >/dev/null || missing="$$missing $$cmd"; \
	done; \
	if [ ! -f /usr/include/gelf.h ]; then missing="$$missing libelf-dev"; fi; \
	if [ -n "$$missing" ]; then \
		echo "WARNING: Kernel build missing:$$missing"; \
		echo "Install with: sudo apt update && sudo apt install -y flex bison libelf-dev libssl-dev bc"; \
	else \
		echo "All kernel build dependencies satisfied!"; \
	fi

init:
	cargo build --release --target $(TARGET_MUSL) -p serenity-init

guard:
	cargo build --release --target $(TARGET_MUSL) -p serenity-guard

spkg:
	CC_x86_64_unknown_linux_musl=clang cargo build --release --target $(TARGET_MUSL) -p spkg

compositor:
	cargo build -p serenity-compositor

shell-ui:
	cargo build -p serenity-shell

capture:
	cargo build --release -p serenity-capture

alacritty:
	cargo install alacritty --root $(BUILD_DIR)/userland --locked

sysd:
	cargo build --release --target $(TARGET_MUSL) -p serenity-sysd

desktop-release: disk sysd
	cargo build --release -p serenity-compositor -p serenity-shell

run-compositor: compositor
	cargo run -p serenity-compositor

run-desktop: compositor shell-ui
	cargo run -p serenity-compositor -- ./target/debug/serenity-login

nushell:
	@chmod +x scripts/fetch-nushell.sh
	@./scripts/fetch-nushell.sh

coreutils:
	@chmod +x scripts/fetch-coreutils.sh
	@./scripts/fetch-coreutils.sh

kernel:
	@chmod +x kernel/build.sh
	@./kernel/build.sh

disk: init spkg guard nushell coreutils
	@chmod +x scripts/build-rootfs.sh
	@./scripts/build-rootfs.sh disk

# GNU runtime layer (glibc, Mesa, dbus, seatd, NetworkManager, compositor...) comes from the
# CI-built `serenity-base` package. LOCAL_BUNDLE=1 restores the old behaviour of copying
# it from this machine with scripts/bundle-compositor.sh.
LOCAL_BUNDLE ?= 0

disk-gui: disk
	@chmod +x scripts/bundle-compositor.sh scripts/preinstall-packages.py
	@if [ "$(LOCAL_BUNDLE)" = "1" ]; then \
		echo "[rootfs] LOCAL_BUNDLE=1: bundling GNU runtime from this host"; \
		$(MAKE) desktop-release && ./scripts/bundle-compositor.sh $(BUILD_DIR)/rootfs-stage; \
	else \
		python3 scripts/preinstall-packages.py $(BUILD_DIR)/rootfs-stage serenity-base || { \
			echo "[rootfs] ERROR: serenity-base not in package index. Run the CI workflow for it, or use 'make disk-gui LOCAL_BUNDLE=1'."; \
			exit 1; }; \
	fi
	@python3 scripts/preinstall-packages.py $(BUILD_DIR)/rootfs-stage alacritty cosmic-desktop
	@python3 scripts/preinstall-packages.py $(BUILD_DIR)/rootfs-stage cosmic-settings cosmic-randr pop-launcher || \
		echo "[rootfs] WARN: cosmic-settings/cosmic-randr/pop-launcher not in package index yet (run CI)"
	@python3 scripts/preinstall-packages.py $(BUILD_DIR)/rootfs-stage kmod linux linux-firmware || \
		echo "[rootfs] WARN: kmod/linux/linux-firmware not in package index yet (run CI); using host modules"
	@mkdir -p $(BUILD_DIR)/rootfs-stage/lib/modules/serenity $(BUILD_DIR)/rootfs-stage/etc/serenity
	@if [ -e $(BUILD_DIR)/rootfs-stage/boot/vmlinuz-serenity ]; then \
		echo "[rootfs] Serenity kernel package installed: drivers load via kmod coldplug/hotplug"; \
		: > $(BUILD_DIR)/rootfs-stage/etc/serenity/modules.load; \
	else \
	KVER=$$(uname -r); \
	: > $(BUILD_DIR)/rootfs-stage/etc/serenity/modules.load; \
	for m in virtio_gpu virtio_input psmouse; do \
		modprobe -S "$$KVER" --show-depends "$$m" 2>/dev/null | awk '$$1=="insmod"{print $$2}' | while read -r p; do \
			[ -f "$$p" ] || continue; \
			base=$$(basename "$$p" .zst); \
			zstd -dq -c "$$p" > "$(BUILD_DIR)/rootfs-stage/lib/modules/serenity/$$base" 2>/dev/null || cp "$$p" "$(BUILD_DIR)/rootfs-stage/lib/modules/serenity/$$base"; \
			echo "/lib/modules/serenity/$$base" >> $(BUILD_DIR)/rootfs-stage/etc/serenity/modules.load; \
		done; \
	done; \
	fi
	@rm -f $(DISK_GUI)
	@truncate -s 6144M $(DISK_GUI)
	@/usr/sbin/mke2fs -q -t ext4 -d $(BUILD_DIR)/rootfs-stage -L SERENITY -F $(DISK_GUI)
	@printf 'sif init uid 0\nsif init gid 0\nsif init mode 0104755\n' | /usr/sbin/debugfs -w $(DISK_GUI) >/dev/null 2>&1
	@echo "[rootfs] Built GUI ext4 disk: $(DISK_GUI) (6144M)"

initramfs: init spkg nushell coreutils
	@chmod +x scripts/build-rootfs.sh
	@./scripts/build-rootfs.sh initramfs

packages:
	@python3 scripts/build-package.py

run: disk
	@test -r "$(KERNEL)" || (echo "ERROR: Kernel not found/readable at $(KERNEL)." && exit 1)
	$(QEMU) \
		$(QEMU_ACCEL) \
		-kernel "$(KERNEL)" \
		-drive "file=$(DISK_IMG),format=raw,if=virtio" \
		-m "$(QEMU_MEM)" \
		-nographic \
		-no-reboot \
		-netdev user,id=net0 \
		-device virtio-net-pci,netdev=net0 \
		-append "root=/dev/vda rw rootfstype=ext4 init=/init console=ttyS0 quiet loglevel=3"

$(DISK_GUI):
	@$(MAKE) disk-gui

run-gui: $(DISK_GUI)
	@test -r "$(KERNEL)" || (echo "ERROR: Kernel not found/readable at $(KERNEL)." && exit 1)
	$(QEMU) \
		$(QEMU_ACCEL) \
		-kernel "$(KERNEL)" \
		-drive "file=$(DISK_GUI),format=raw,if=virtio" \
		-m 2048M \
		-smp 2 \
		-device virtio-vga-gl,xres=1920,yres=1080 \
		-device virtio-tablet-pci \
		-device virtio-keyboard-pci \
		-display gtk,gl=on \
		-no-reboot \
		-netdev user,id=net0 \
		-device virtio-net-pci,netdev=net0 \
		-append "root=/dev/vda rw rootfstype=ext4 init=/init quiet loglevel=3"

run-initramfs: initramfs
	@test -r "$(KERNEL)" || (echo "ERROR: Kernel not found/readable at $(KERNEL)." && exit 1)
	$(QEMU) \
		$(QEMU_ACCEL) \
		-kernel "$(KERNEL)" \
		-initrd "$(INITRAMFS)" \
		-m "$(QEMU_MEM)" \
		-nographic \
		-no-reboot \
		-netdev user,id=net0 \
		-device virtio-net-pci,netdev=net0 \
		-append "console=ttyS0 quiet loglevel=3"

smoke-test: disk
	@test -r "$(KERNEL)" || (echo "ERROR: Kernel not found/readable at $(KERNEL)." && exit 1)
	@echo "==> Running automated Phase 2 QEMU smoke test..."
	@python3 scripts/smoke-test.py "$(KERNEL)" "$(DISK_IMG)"

clean:
	rm -rf $(BUILD_DIR)
	cargo clean
