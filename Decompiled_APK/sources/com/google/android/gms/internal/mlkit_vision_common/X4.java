package com.google.android.gms.internal.mlkit_vision_common;

/* loaded from: classes2.dex */
public final class X4 extends R4 {
    public final transient Object[] c;
    public final transient int d;
    public final transient int e = 1;

    public X4(Object[] objArr, int i) {
        this.c = objArr;
        this.d = i;
    }

    @Override // java.util.List
    public final Object get(int i) {
        N3.f(i, this.e);
        Object obj = this.c[i + i + this.d];
        obj.getClass();
        return obj;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.e;
    }
}
