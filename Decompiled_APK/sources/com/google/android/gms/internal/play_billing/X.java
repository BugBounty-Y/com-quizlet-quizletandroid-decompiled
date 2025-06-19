package com.google.android.gms.internal.play_billing;

import java.util.Iterator;

/* loaded from: classes2.dex */
public final class X extends G {
    public static final Object[] h;
    public static final X i;
    public final transient Object[] c;
    public final transient int d;
    public final transient Object[] e;
    public final transient int f;
    public final transient int g;

    static {
        Object[] objArr = new Object[0];
        h = objArr;
        i = new X(objArr, 0, objArr, 0, 0);
    }

    public X(Object[] objArr, int i2, Object[] objArr2, int i3, int i4) {
        this.c = objArr;
        this.d = i2;
        this.e = objArr2;
        this.f = i3;
        this.g = i4;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final int a(Object[] objArr) {
        Object[] objArr2 = this.c;
        int i2 = this.g;
        System.arraycopy(objArr2, 0, objArr, 0, i2);
        return i2;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final int b() {
        return this.g;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final int c() {
        return 0;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        if (obj != null) {
            Object[] objArr = this.e;
            if (objArr.length != 0) {
                int iC = Z0.c(obj.hashCode());
                while (true) {
                    int i2 = iC & this.f;
                    Object obj2 = objArr[i2];
                    if (obj2 == null) {
                        return false;
                    }
                    if (obj2.equals(obj)) {
                        return true;
                    }
                    iC = i2 + 1;
                }
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3844w
    public final Object[] h() {
        return this.c;
    }

    @Override // com.google.android.gms.internal.play_billing.G, java.util.Collection, java.util.Set
    public final int hashCode() {
        return this.d;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final /* synthetic */ Iterator iterator() {
        return e().listIterator(0);
    }

    @Override // com.google.android.gms.internal.play_billing.G
    public final B k() {
        return B.m(this.g, this.c);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return this.g;
    }
}
