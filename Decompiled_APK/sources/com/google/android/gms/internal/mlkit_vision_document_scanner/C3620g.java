package com.google.android.gms.internal.mlkit_vision_document_scanner;

import java.util.Iterator;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.g, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3620g extends AbstractC3596d {
    public final transient com.google.android.gms.internal.mlkit_vision_barcode.G c;
    public final transient Object[] d;
    public final transient int e = 1;

    public C3620g(com.google.android.gms.internal.mlkit_vision_barcode.G g, Object[] objArr) {
        this.c = g;
        this.d = objArr;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.x7
    public final int a(Object[] objArr) {
        AbstractC3588c c3612f = this.b;
        if (c3612f == null) {
            c3612f = new C3612f(this);
            this.b = c3612f;
        }
        return c3612f.a(objArr);
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
        AbstractC3588c c3612f = this.b;
        if (c3612f == null) {
            c3612f = new C3612f(this);
            this.b = c3612f;
        }
        return c3612f.listIterator(0);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return this.e;
    }
}
