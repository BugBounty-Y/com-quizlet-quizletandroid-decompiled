package com.google.android.gms.internal.mlkit_common;

import com.google.android.gms.internal.mlkit_vision_common.E3;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class g extends d {
    public static final g e = new g(new Object[0], 0);
    public final transient Object[] c;
    public final transient int d;

    public g(Object[] objArr, int i) {
        this.c = objArr;
        this.d = i;
    }

    @Override // com.google.android.gms.internal.mlkit_common.d, com.google.android.gms.internal.mlkit_common.a
    public final int a(Object[] objArr) {
        Object[] objArr2 = this.c;
        int i = this.d;
        System.arraycopy(objArr2, 0, objArr, 0, i);
        return i;
    }

    @Override // com.google.android.gms.internal.mlkit_common.a
    public final int b() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.mlkit_common.a
    public final int c() {
        return 0;
    }

    @Override // com.google.android.gms.internal.mlkit_common.a
    public final Object[] e() {
        return this.c;
    }

    @Override // java.util.List
    public final Object get(int i) {
        E3.a(i, this.d);
        Object obj = this.c[i];
        Objects.requireNonNull(obj);
        return obj;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}
