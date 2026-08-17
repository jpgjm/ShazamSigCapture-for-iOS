THEOS_PACKAGE_SCHEME = rootless
FINALPACKAGE = 1
TARGET := iphone:clang:latest:14.0
ARCHS = arm64
INSTALL_TARGET_PROCESSES = Shazam

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ShazamSigCapture

ShazamSigCapture_FILES = Tweak.xm
ShazamSigCapture_CFLAGS = -fobjc-arc
ShazamSigCapture_FRAMEWORKS = UIKit Foundation

include $(THEOS_MAKE_PATH)/tweak.mk
