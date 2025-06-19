package com.google.android.gms.internal.mlkit_vision_common;

/* loaded from: classes2.dex */
public final class T4 extends R4 {
    public static final T4 e = new T4(new Object[0], 0);
    public final transient Object[] c;
    public final transient int d;

    public T4(Object[] objArr, int i) {
        this.c = objArr;
        this.d = i;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.R4, com.google.android.gms.internal.mlkit_vision_common.AbstractC3478j4
    public final int a(Object[] objArr) {
        Object[] objArr2 = this.c;
        int i = this.d;
        System.arraycopy(objArr2, 0, objArr, 0, i);
        return i;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.AbstractC3478j4
    public final int b() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.AbstractC3478j4
    public final int c() {
        return 0;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.AbstractC3478j4
    public final Object[] e() {
        return this.c;
    }

    @Override // java.util.List
    public final Object get(int i) {
        N3.f(i, this.d);
        Object obj = this.c[i];
        obj.getClass();
        return obj;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}
