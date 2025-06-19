package com.google.android.gms.internal.ads;

import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.Map;

/* loaded from: classes2.dex */
public abstract class St implements Map.Entry {
    @Override // java.util.Map.Entry
    public final boolean equals(Object obj) {
        if (obj instanceof Map.Entry) {
            Map.Entry entry = (Map.Entry) obj;
            if (AbstractC2457os.l(getKey(), entry.getKey()) && AbstractC2457os.l(getValue(), entry.getValue())) {
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
