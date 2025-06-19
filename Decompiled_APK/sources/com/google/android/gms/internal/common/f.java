package com.google.android.gms.internal.common;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3524r3;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class f extends e {
    public static final f e = new f(new Object[0], 0);
    public final transient Object[] c;
    public final transient int d;

    public f(Object[] objArr, int i) {
        this.c = objArr;
        this.d = i;
    }

    @Override // com.google.android.gms.internal.common.a
    public final Object[] a() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.common.a
    public final int b() {
        return 0;
    }

    @Override // com.google.android.gms.internal.common.a
    public final int c() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.common.e, com.google.android.gms.internal.common.a
    public final int e(Object[] objArr) {
        Object[] objArr2 = this.c;
        int i = this.d;
        System.arraycopy(objArr2, 0, objArr, 0, i);
        return i;
    }

    @Override // java.util.List
    public final Object get(int i) {
        AbstractC3524r3.b(i, this.d);
        Object obj = this.c[i];
        Objects.requireNonNull(obj);
        return obj;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}
