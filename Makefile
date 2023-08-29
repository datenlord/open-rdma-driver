KERNEL_SRC_DIR ?= /linux-src

.PHONY: driver user gdb

driver:
	$(MAKE) -C $(KERNEL_SRC_DIR) M=$(PWD)/driver

user:
	./rdma-core/build.sh

qemu:
	./scripts/run_qemu.sh

gdb:
	./scripts/run_gdb.sh

# language server config, e.g., clangd
lsp:
	cd $(KERNEL_SRC_DIR) && ./scripts/clang-tools/gen_compile_commands.py