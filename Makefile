TARGET := iphone:clang:latest:14.0
ARCHS = arm64
INSTALL_TARGET_PROCESSES = YallaLudo

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = DomainSniffer

DomainSniffer_FILES = Tweak.xm
DomainSniffer_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
DomainSniffer_FRAMEWORKS = UIKit Foundation

include $(THEOS_MAKE_PATH)/tweak.mk
