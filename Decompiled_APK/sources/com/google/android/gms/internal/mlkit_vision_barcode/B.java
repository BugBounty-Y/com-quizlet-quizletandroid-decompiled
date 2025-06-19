package com.google.android.gms.internal.mlkit_vision_barcode;

import java.util.Objects;

/* loaded from: classes2.dex */
public final class B extends AbstractC3292x {
    public static final B e = new B(new Object[0], 0);
    public final transient Object[] c;
    public final transient int d;

    public B(Object[] objArr, int i) {
        this.c = objArr;
        this.d = i;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3292x, com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3252s
    public final int a(Object[] objArr, int i) {
        Object[] objArr2 = this.c;
        int i2 = this.d;
        System.arraycopy(objArr2, 0, objArr, i, i2);
        return i + i2;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3252s
    public final int b() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3252s
    public final int c() {
        return 0;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3252s
    public final Object[] e() {
        return this.c;
    }

    @Override // java.util.List
    public final Object get(int i) {
        com.google.android.gms.internal.mlkit_vision_common.I3.d(i, this.d);
        Object obj = this.c[i];
        Objects.requireNonNull(obj);
        return obj;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}
