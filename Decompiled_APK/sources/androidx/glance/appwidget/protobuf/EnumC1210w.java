package androidx.glance.appwidget.protobuf;

import com.skydoves.balloon.internals.DefinitionKt;
import java.io.Serializable;

/* renamed from: androidx.glance.appwidget.protobuf.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public enum EnumC1210w {
    VOID(Void.class, null),
    INT(Integer.class, 0),
    LONG(Long.class, 0L),
    FLOAT(Float.class, Float.valueOf(DefinitionKt.NO_Float_VALUE)),
    DOUBLE(Double.class, Double.valueOf(0.0d)),
    BOOLEAN(Boolean.class, Boolean.FALSE),
    STRING(String.class, ""),
    BYTE_STRING(C1194f.class, C1194f.c),
    ENUM(Integer.class, null),
    MESSAGE(Object.class, null);

    EnumC1210w(Class cls, Serializable serializable) {
    }
}
