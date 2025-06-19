package com.google.android.gms.internal.ads;

import java.util.Iterator;

/* loaded from: classes2.dex */
public final class Hu extends AbstractC2459ou {
    public static final Object[] i;
    public static final Hu j;
    public final transient Object[] d;
    public final transient int e;
    public final transient Object[] f;
    public final transient int g;
    public final transient int h;

    static {
        Object[] objArr = new Object[0];
        i = objArr;
        j = new Hu(objArr, 0, objArr, 0, 0);
    }

    public Hu(Object[] objArr, int i2, Object[] objArr2, int i3, int i4) {
        this.d = objArr;
        this.e = i2;
        this.f = objArr2;
        this.g = i3;
        this.h = i4;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final int a(Object[] objArr, int i2) {
        Object[] objArr2 = this.d;
        int i3 = this.h;
        System.arraycopy(objArr2, 0, objArr, i2, i3);
        return i2 + i3;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final int b() {
        return this.h;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final int c() {
        return 0;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        if (obj != null) {
            Object[] objArr = this.f;
            if (objArr.length != 0) {
                int iM = AbstractC2457os.m(obj);
                while (true) {
                    int i2 = iM & this.g;
                    Object obj2 = objArr[i2];
                    if (obj2 == null) {
                        return false;
                    }
                    if (obj2.equals(obj)) {
                        return true;
                    }
                    iM = i2 + 1;
                }
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final Pu g() {
        return e().listIterator(0);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final boolean h() {
        return false;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2459ou, java.util.Collection, java.util.Set
    public final int hashCode() {
        return this.e;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final /* synthetic */ Iterator iterator() {
        return e().listIterator(0);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2071fu
    public final Object[] j() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2459ou
    public final AbstractC2330lu m() {
        return AbstractC2330lu.m(this.h, this.d);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return this.h;
    }
}
