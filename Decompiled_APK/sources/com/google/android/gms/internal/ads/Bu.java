package com.google.android.gms.internal.ads;

import java.util.Objects;

/* loaded from: classes2.dex */
public final class Bu extends AbstractC2330lu {
    public static final Bu e = new Bu(new Object[0], 0);
    public final transient Object[] c;
    public final transient int d;

    public Bu(Object[] objArr, int i) {
        this.c = objArr;
        this.d = i;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2330lu, com.google.android.gms.internal.ads.AbstractC2071fu
    public final int a(Object[] objArr, int i) {
        Object[] objArr2 = this.c;
        int i2 = this.d;
        System.arraycopy(objArr2, 0, objArr, i, i2);
        return i + i2;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final int b() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final int c() {
        return 0;
    }

    @Override // java.util.List
    public final Object get(int i) {
        AbstractC1981ds.f(i, this.d);
        Object obj = this.c[i];
        Objects.requireNonNull(obj);
        return obj;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final boolean h() {
        return false;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final Object[] j() {
        return this.c;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}
