package androidx.datastore.preferences.protobuf;

import com.skydoves.balloon.internals.DefinitionKt;
import java.io.Serializable;

/* loaded from: classes.dex */
public enum p0 {
    INT(0),
    LONG(0L),
    FLOAT(Float.valueOf(DefinitionKt.NO_Float_VALUE)),
    DOUBLE(Double.valueOf(0.0d)),
    BOOLEAN(Boolean.FALSE),
    STRING(""),
    BYTE_STRING(C1100g.c),
    ENUM(null),
    MESSAGE(null);

    p0(Serializable serializable) {
    }
}
