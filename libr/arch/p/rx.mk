OBJ_RX=p/rx/plugin.o

STATIC_OBJ+=$(OBJ_RX)

TARGET_RX=p/arch_rx.$(EXT_SO)

$(TARGET_RX): $(OBJ_RX)
	${CC} $(call libname,arch_rx) ${LDFLAGS} ${CFLAGS} -o $(TARGET_RX) $(OBJ_RX)
