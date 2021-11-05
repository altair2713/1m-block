TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lnetfilter_queue

SOURCES += \
	1m-block.cpp \
	main.cpp
	
HEADERS += 1m-block.h
