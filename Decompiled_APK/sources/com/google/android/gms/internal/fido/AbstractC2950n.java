package com.google.android.gms.internal.fido;

import java.io.Serializable;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.fido.n, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2950n implements Map, Serializable {
    public static final Map.Entry[] b = new Map.Entry[0];
    public transient AbstractC2951o a;

    @Override // java.util.Map
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final AbstractC2951o entrySet() {
        AbstractC2951o c2953q = this.a;
        if (c2953q == null) {
            r rVar = (r) this;
            c2953q = rVar.isEmpty() ? C2960y.j : new C2953q(rVar);
            this.a = c2953q;
        }
        return c2953q;
    }

    @Override // java.util.Map
    public final void clear() {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.Map
    public final boolean containsKey(Object obj) {
        return get(obj) != null;
    }

    @Override // java.util.Map
    public final boolean containsValue(Object obj) {
        return ((r) this).d.contains(obj);
    }

    @Override // java.util.Map
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof Map) {
            return ((r) this).entrySet().equals(((Map) obj).entrySet());
        }
        return false;
    }

    @Override // java.util.Map
    public abstract Object get(Object obj);

    @Override // java.util.Map
    public final Object getOrDefault(Object obj, Object obj2) {
        Object obj3 = get(obj);
        return obj3 != null ? obj3 : obj2;
    }

    @Override // java.util.Map
    public final int hashCode() {
        return AbstractC2937a.b(entrySet());
    }

    @Override // java.util.Map
    public final boolean isEmpty() {
        return ((r) this).size() == 0;
    }

    @Override // java.util.Map
    public final Object put(Object obj, Object obj2) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.Map
    public final void putAll(Map map) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.Map
    public final Object remove(Object obj) {
        throw new UnsupportedOperationException();
    }

    public final String toString() {
        r rVar = (r) this;
        int size = rVar.size();
        if (size < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(size, "size cannot be negative but was: "));
        }
        StringBuilder sb = new StringBuilder((int) Math.min(size * 8, 1073741824L));
        sb.append('{');
        boolean z = true;
        for (Map.Entry entry : rVar.entrySet()) {
            if (!z) {
                sb.append(", ");
            }
            sb.append(entry.getKey());
            sb.append('=');
            sb.append(entry.getValue());
            z = false;
        }
        sb.append('}');
        return sb.toString();
    }
}
