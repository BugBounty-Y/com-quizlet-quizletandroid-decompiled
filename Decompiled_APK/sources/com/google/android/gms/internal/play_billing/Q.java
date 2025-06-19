package com.google.android.gms.internal.play_billing;

import java.util.Objects;

/* loaded from: classes2.dex */
public final class Q extends B {
    public static final Q e = new Q(new Object[0], 0);
    public final transient Object[] c;
    public final transient int d;

    public Q(Object[] objArr, int i) {
        this.c = objArr;
        this.d = i;
    }

    @Override // com.google.android.gms.internal.play_billing.B, com.google.android.gms.internal.play_billing.AbstractC3844w
    public final int a(Object[] objArr) {
        Object[] objArr2 = this.c;
        int i = this.d;
        System.arraycopy(objArr2, 0, objArr, 0, i);
        return i;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final int b() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final int c() {
        return 0;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final boolean g() {
        return false;
    }

    @Override // java.util.List
    public final Object get(int i) {
        Z0.h(i, this.d);
        Object obj = this.c[i];
        Objects.requireNonNull(obj);
        return obj;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final Object[] h() {
        return this.c;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}
