package com.google.android.gms.internal.mlkit_vision_barcode;

import java.util.AbstractMap;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class C extends AbstractC3292x {
    public final /* synthetic */ D c;

    public C(D d) {
        this.c = d;
    }

    @Override // java.util.List
    public final /* bridge */ /* synthetic */ Object get(int i) {
        D d = this.c;
        com.google.android.gms.internal.mlkit_vision_common.I3.d(i, d.e);
        int i2 = i + i;
        Object[] objArr = d.d;
        Object obj = objArr[i2];
        Objects.requireNonNull(obj);
        Object obj2 = objArr[i2 + 1];
        Objects.requireNonNull(obj2);
        return new AbstractMap.SimpleImmutableEntry(obj, obj2);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.c.e;
    }
}
