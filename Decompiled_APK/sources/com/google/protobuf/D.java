package com.google.protobuf;

import com.skydoves.balloon.internals.DefinitionKt;
import java.io.Serializable;

/* loaded from: classes2.dex */
public enum D {
    VOID(Void.class, null),
    INT(Integer.class, 0),
    LONG(Long.class, 0L),
    FLOAT(Float.class, Float.valueOf(DefinitionKt.NO_Float_VALUE)),
    DOUBLE(Double.class, Double.valueOf(0.0d)),
    BOOLEAN(Boolean.class, Boolean.FALSE),
    STRING(String.class, ""),
    BYTE_STRING(C4012f.class, C4012f.c),
    ENUM(Integer.class, null),
    MESSAGE(Object.class, null);

    D(Class cls, Serializable serializable) {
    }
}
