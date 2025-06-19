package com.google.android.gms.internal.play_billing;

import java.util.Objects;

/* loaded from: classes2.dex */
public final class V extends B {
    public final transient Object[] c;
    public final transient int d;
    public final transient int e;

    public V(Object[] objArr, int i, int i2) {
        this.c = objArr;
        this.d = i;
        this.e = i2;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final boolean g() {
        return true;
    }

    @Override // java.util.List
    public final Object get(int i) {
        Z0.h(i, this.e);
        Object obj = this.c[i + i + this.d];
        Objects.requireNonNull(obj);
        return obj;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.e;
    }
}
