package com.google.android.gms.internal.ads;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class Px {
    public static final Px b = new Px(Collections.unmodifiableMap(new HashMap()));
    public final Map a;

    public /* synthetic */ Px(Map map) {
        this.a = map;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof Px) {
            return this.a.equals(((Px) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return this.a.toString();
    }
}
