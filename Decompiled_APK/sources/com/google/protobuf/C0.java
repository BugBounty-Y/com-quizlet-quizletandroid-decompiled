package com.google.protobuf;

import com.skydoves.balloon.internals.DefinitionKt;
import java.io.Serializable;

/* loaded from: classes2.dex */
public enum C0 {
    INT(0),
    LONG(0L),
    FLOAT(Float.valueOf(DefinitionKt.NO_Float_VALUE)),
    DOUBLE(Double.valueOf(0.0d)),
    BOOLEAN(Boolean.FALSE),
    STRING(""),
    BYTE_STRING(C4012f.c),
    ENUM(null),
    MESSAGE(null);

    C0(Serializable serializable) {
    }
}
