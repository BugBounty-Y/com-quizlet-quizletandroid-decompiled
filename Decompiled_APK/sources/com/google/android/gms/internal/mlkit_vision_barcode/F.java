package com.google.android.gms.internal.mlkit_vision_barcode;

import java.util.Objects;

/* loaded from: classes2.dex */
public final class F extends AbstractC3292x {
    public final transient Object[] c;
    public final transient int d;
    public final transient int e = 1;

    public F(Object[] objArr, int i) {
        this.c = objArr;
        this.d = i;
    }

    @Override // java.util.List
    public final Object get(int i) {
        com.google.android.gms.internal.mlkit_vision_common.I3.d(i, this.e);
        Object obj = this.c[i + i + this.d];
        Objects.requireNonNull(obj);
        return obj;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.e;
    }
}
