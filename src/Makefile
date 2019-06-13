CC = g++
CFLAGS = -Wall -g -fPIC
INC = -I./inc/
LIBS = -lMESA_handle_logger -lMESA_prof_load
OBJS = http_jt_audit.o
TARGET = http_jt_audit.so
PAPP_PATH=/home/dj/sapp_run
PLUGIN_PATH=./plug/business
CONFLIST_NAME=conflist_business.inf
PLUGIN_DIR_NAME=http_jt_audit
PLUGIN_INF_NAME=http_jt_audit.inf
 
TARGET_DIR=$(PAPP_PATH)/$(PLUGIN_PATH)/$(PLUGIN_DIR_NAME)/
INSERT_FILE=$(PAPP_PATH)/$(PLUGIN_PATH)/$(CONFLIST_NAME)
INSERT_CONTENT=$(PLUGIN_PATH)/$(PLUGIN_DIR_NAME)/$(PLUGIN_INF_NAME)
 

.cpp.o:
	$(CC) -c $(INC) $(CFLAGS) $<

all: $(TARGET)


$(TARGET): $(OBJS)
	$(CC) -O2 -o $@ $^ $(LIBS) -shared -fPIC
	cp $(TARGET) ../bin/

install:
	mkdir -p  $(TARGET_DIR) 
	cp -r ../bin/jt_http_plug.so   $(TARGET_DIR)
	cp -r ../bin/jt_http_plug.inf   $(TARGET_DIR)
	@ret=`cat $(INSERT_FILE)|grep $(INSERT_CONTENT)|wc -l`;if [ $$ret -eq 0 ];then echo $(INSERT_CONTENT) >>$(INSERT_FILE);fi

.PHONY:clean

clean:
	-rm -rf $(OBJS) $(TARGET)
