#Android makefile to build lk bootloader as a part of Android Build

ifeq ($(BOOTLOADER_GCC_VERSION),)
ifndef $(2ND_TARGET_GCC_VERSION)
CROSS_COMPILE := ../../../prebuilts/gcc/linux-x86/arm/arm-eabi-$(TARGET_GCC_VERSION)/bin/arm-eabi-
else
CROSS_COMPILE := ../../../prebuilts/gcc/linux-x86/arm/arm-eabi-$(2ND_TARGET_GCC_VERSION)/bin/arm-eabi-
endif
else # BOOTLOADER_GCC_VERSION defined
CROSS_COMPILE := ../../../prebuilts/gcc/linux-x86/arm/$(BOOTLOADER_GCC_VERSION)/bin/arm-eabi-
endif

# Set flags if we need to include security libs
ifeq ($(TARGET_BOOTIMG_SIGNED),true)
  SIGNED_KERNEL := SIGNED_KERNEL=1
else
  SIGNED_KERNEL := SIGNED_KERNEL=0
endif

ifeq ($(BOOTLOADER_PLATFORM),)
  BOOTLOADER_PLATFORM := $(TARGET_BOARD_PLATFORM)
endif

ifeq ($(PRODUCTS.$(INTERNAL_PRODUCT).PRODUCT_SUPPORTS_VERITY),true)
  VERIFIED_BOOT := VERIFIED_BOOT=1
else
  VERIFIED_BOOT := VERIFIED_BOOT=0
endif

ifeq (1,$(filter 1,$(shell echo "$$(( $(PLATFORM_SDK_VERSION) >= 24 ))" )))
  OSVERSION_IN_BOOTIMAGE := OSVERSION_IN_BOOTIMAGE=1
  ENABLE_VB_ATTEST := ENABLE_VB_ATTEST=1
else
  OSVERSION_IN_BOOTIMAGE := OSVERSION_IN_BOOTIMAGE=0
  ENABLE_VB_ATTEST := ENABLE_VB_ATTEST=0
endif

ifneq ($(TARGET_BUILD_VARIANT),user)
  DEVICE_STATUS := DEFAULT_UNLOCK=true
endif

ifeq ($(TARGET_BUILD_VARIANT),user)
  BUILD_VARIANT := USER_BUILD_VARIANT=true
endif

ifeq ($(TARGET_BOARD_PLATFORM),msm8660)
  BOOTLOADER_PLATFORM := msm8660_surf
endif

ifeq ($(TARGET_BOOTLOADER_BOARD_NAME),)
  BOARD_NAME := BOARD_NAME=$(PRODUCT_NAME)
else
  BOARD_NAME := BOARD_NAME=$(TARGET_BOOTLOADER_BOARD_NAME)
endif

ABOOT_OUT := $(TARGET_OUT_INTERMEDIATES)/ABOOT_OBJ
$(ABOOT_OUT):
	$(hide) mkdir -p $(ABOOT_OUT)

ABOOT_CLEAN:
	$(hide) rm -f $(TARGET_ABOOT_ELF)

# ELF binary for ABOOT
TARGET_ABOOT_ELF := $(PRODUCT_OUT)/aboot.elf
$(TARGET_ABOOT_ELF): ABOOT_CLEAN | $(ABOOT_OUT)
	$(MAKE) -C bootable/bootloader/lk TOOLCHAIN_PREFIX=$(CROSS_COMPILE) BOOTLOADER_OUT=../../../$(ABOOT_OUT) $(BOOTLOADER_PLATFORM) $(EMMC_BOOT) $(SIGNED_KERNEL) $(VERIFIED_BOOT) $(DEVICE_STATUS) $(BUILD_VARIANT) $(BOARD_NAME) $(ENABLE_VB_ATTEST) $(OSVERSION_IN_BOOTIMAGE)

# NAND variant output
TARGET_NAND_BOOTLOADER := $(PRODUCT_OUT)/appsboot.mbn
NAND_BOOTLOADER_OUT := $(TARGET_OUT_INTERMEDIATES)/NAND_BOOTLOADER_OBJ

# Remove bootloader binary to trigger recompile when source changes
appsbootldr_clean:
	$(hide) rm -f $(TARGET_NAND_BOOTLOADER)

$(NAND_BOOTLOADER_OUT):
	mkdir -p $(NAND_BOOTLOADER_OUT)

# eMMC variant output
TARGET_EMMC_BOOTLOADER := $(PRODUCT_OUT)/emmc_appsboot.mbn
EMMC_BOOTLOADER_OUT := $(TARGET_OUT_INTERMEDIATES)/EMMC_BOOTLOADER_OBJ

emmc_appsbootldr_clean:
	$(hide) rm -f $(TARGET_EMMC_BOOTLOADER)

$(EMMC_BOOTLOADER_OUT):
	mkdir -p $(EMMC_BOOTLOADER_OUT)

# Top level for NAND variant targets
$(TARGET_NAND_BOOTLOADER): appsbootldr_clean | $(NAND_BOOTLOADER_OUT)
	$(MAKE) -C bootable/bootloader/lk TOOLCHAIN_PREFIX=$(CROSS_COMPILE) BOOTLOADER_OUT=../../../$(NAND_BOOTLOADER_OUT) $(BOOTLOADER_PLATFORM) $(SIGNED_KERNEL) $(BOARD_NAME)

# Top level for eMMC variant targets
$(TARGET_EMMC_BOOTLOADER): emmc_appsbootldr_clean | $(EMMC_BOOTLOADER_OUT) $(INSTALLED_KEYSTOREIMAGE_TARGET)
	$(MAKE) -C bootable/bootloader/lk TOOLCHAIN_PREFIX=$(CROSS_COMPILE) BOOTLOADER_OUT=../../../$(EMMC_BOOTLOADER_OUT) $(BOOTLOADER_PLATFORM) EMMC_BOOT=1 $(SIGNED_KERNEL) $(VERIFIED_BOOT) $(DEVICE_STATUS) $(BUILD_VARIANT) $(BOARD_NAME)

# Keep build NAND & eMMC as default for targets still using TARGET_BOOTLOADER
TARGET_BOOTLOADER := $(PRODUCT_OUT)/EMMCBOOT.MBN
$(TARGET_BOOTLOADER): $(NAND_BOOTLOADER_OUT) $(EMMC_BOOTLOADER_OUT) | $(TARGET_NAND_BOOTLOADER) $(TARGET_EMMC_BOOTLOADER)

#
# Build nandwrite as a part of Android Build for NAND configurations
#
TARGET_NANDWRITE := $(PRODUCT_OUT)/obj/nandwrite/build-$(BOOTLOADER_PLATFORM)_nandwrite/lk
NANDWRITE_OUT := $(TARGET_OUT_INTERMEDIATES)/nandwrite

nandwrite_clean:
	$(hide) rm -f $(TARGET_NANDWRITE)
	$(hide) rm -rf $(NANDWRITE_OUT)

$(NANDWRITE_OUT):
	mkdir -p $(NANDWRITE_OUT)

$(TARGET_NANDWRITE): nandwrite_clean | $(NANDWRITE_OUT)
	@echo $(BOOTLOADER_PLATFORM)_nandwrite
	$(MAKE) -C bootable/bootloader/lk TOOLCHAIN_PREFIX=$(CROSS_COMPILE) BOOTLOADER_OUT=../../../$(NANDWRITE_OUT) $(BOOTLOADER_PLATFORM)_nandwrite BUILD_NANDWRITE=1
