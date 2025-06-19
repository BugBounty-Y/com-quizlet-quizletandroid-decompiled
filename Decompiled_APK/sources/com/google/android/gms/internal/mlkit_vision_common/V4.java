package com.google.android.gms.internal.mlkit_vision_common;

import java.util.Iterator;
import java.util.Map;

/* loaded from: classes2.dex */
public final class V4 extends S4 {
    public final transient com.google.android.gms.internal.mlkit_vision_barcode.G c;
    public final transient Object[] d;
    public final transient int e = 1;

    public V4(com.google.android.gms.internal.mlkit_vision_barcode.G g, Object[] objArr) {
        this.c = g;
        this.d = objArr;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.AbstractC3478j4
    public final int a(Object[] objArr) {
        R4 u4 = this.b;
        if (u4 == null) {
            u4 = new U4(this);
            this.b = u4;
        }
        return u4.a(objArr);
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
        R4 u4 = this.b;
        if (u4 == null) {
            u4 = new U4(this);
            this.b = u4;
        }
        return u4.listIterator(0);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return this.e;
    }
}
