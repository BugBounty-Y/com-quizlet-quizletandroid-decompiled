package com.google.android.gms.internal.mlkit_vision_common;

import java.util.Iterator;

/* loaded from: classes2.dex */
public final class W4 extends S4 {
    public final transient com.google.android.gms.internal.mlkit_vision_barcode.G c;
    public final transient X4 d;

    public W4(com.google.android.gms.internal.mlkit_vision_barcode.G g, X4 x4) {
        this.c = g;
        this.d = x4;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.AbstractC3478j4
    public final int a(Object[] objArr) {
        return this.d.a(objArr);
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
        this.c.getClass();
        return 1;
    }
}
