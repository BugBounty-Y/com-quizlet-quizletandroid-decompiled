package com.google.android.gms.internal.mlkit_vision_barcode;

import java.util.Iterator;

/* loaded from: classes2.dex */
public final class E extends AbstractC3300y {
    public final transient G c;
    public final transient F d;

    public E(G g, F f) {
        this.c = g;
        this.d = f;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3252s
    public final int a(Object[] objArr, int i) {
        return this.d.a(objArr, i);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        return this.c.get(obj) != null;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final /* synthetic */ Iterator iterator() {
        return this.d.listIterator(0);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return 1;
    }
}
