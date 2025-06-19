package com.google.android.gms.internal.mlkit_vision_barcode;

import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.k, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3181k implements Map.Entry {
    @Override // java.util.Map.Entry
    public final boolean equals(Object obj) {
        if (obj instanceof Map.Entry) {
            Map.Entry entry = (Map.Entry) obj;
            if (com.google.android.gms.internal.mlkit_vision_common.H3.b(getKey(), entry.getKey()) && com.google.android.gms.internal.mlkit_vision_common.H3.b(getValue(), entry.getValue())) {
                return true;
            }
        }
        return false;
    }

    @Override // java.util.Map.Entry
    public final int hashCode() {
        Object key = getKey();
        Object value = getValue();
        return (key == null ? 0 : key.hashCode()) ^ (value != null ? value.hashCode() : 0);
    }

    public final String toString() {
        return android.support.v4.media.session.a.l(String.valueOf(getKey()), SimpleComparison.EQUAL_TO_OPERATION, String.valueOf(getValue()));
    }
}
