package com.google.common.base;

import java.io.Serializable;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class g implements Function, Serializable {
    public final HashMap a;

    public g(HashMap map) {
        map.getClass();
        this.a = map;
    }

    @Override // com.google.common.base.Function
    public final Object apply(Object obj) {
        HashMap map = this.a;
        Object obj2 = map.get(obj);
        if (obj2 != null || map.containsKey(obj)) {
            return obj2;
        }
        throw new IllegalArgumentException(b.j("Key '%s' not present in map", obj));
    }

    @Override // com.google.common.base.Function
    public final boolean equals(Object obj) {
        if (obj instanceof g) {
            return this.a.equals(((g) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Functions.forMap(" + this.a + ")";
    }
}
