package com.google.android.gms.internal.mlkit_common;

import java.util.Iterator;
import java.util.Map;

/* loaded from: classes2.dex */
public final class i extends f {
    public final transient l c;
    public final transient Object[] d;
    public final transient int e;

    public i(l lVar, Object[] objArr, int i) {
        this.c = lVar;
        this.d = objArr;
        this.e = i;
    }

    @Override // com.google.android.gms.internal.mlkit_common.a
    public final int a(Object[] objArr) {
        d hVar = this.b;
        if (hVar == null) {
            hVar = new h(this);
            this.b = hVar;
        }
        return hVar.a(objArr);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        if (obj instanceof Map.Entry) {
            Map.Entry entry = (Map.Entry) obj;
            Object key = entry.getKey();
            Object value = entry.getValue();
            if (value != null && value.equals(this.c.get(key))) {
                return true;
            }
        }
        return false;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        d hVar = this.b;
        if (hVar == null) {
            hVar = new h(this);
            this.b = hVar;
        }
        return hVar.listIterator(0);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return this.e;
    }
}
