package com.google.common.collect;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3514p4;

/* loaded from: classes2.dex */
public final class D extends o {
    public static final Object[] i;
    public static final D j;
    public final transient Object[] d;
    public final transient int e;
    public final transient Object[] f;
    public final transient int g;
    public final transient int h;

    static {
        Object[] objArr = new Object[0];
        i = objArr;
        j = new D(objArr, 0, objArr, 0, 0);
    }

    public D(Object[] objArr, int i2, Object[] objArr2, int i3, int i4) {
        this.d = objArr;
        this.e = i2;
        this.f = objArr2;
        this.g = i3;
        this.h = i4;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final int b(Object[] objArr) {
        Object[] objArr2 = this.d;
        int i2 = this.h;
        System.arraycopy(objArr2, 0, objArr, 0, i2);
        return i2;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final Object[] c() {
        return this.d;
    }

    @Override // com.google.common.collect.AbstractC3923f, java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        if (obj != null) {
            Object[] objArr = this.f;
            if (objArr.length != 0) {
                int iB = AbstractC3514p4.b(obj.hashCode());
                while (true) {
                    int i2 = iB & this.g;
                    Object obj2 = objArr[i2];
                    if (obj2 == null) {
                        return false;
                    }
                    if (obj2.equals(obj)) {
                        return true;
                    }
                    iB = i2 + 1;
                }
            }
        }
        return false;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final int e() {
        return this.h;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final int g() {
        return 0;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final boolean h() {
        return false;
    }

    @Override // com.google.common.collect.o, java.util.Collection, java.util.Set
    public final int hashCode() {
        return this.e;
    }

    @Override // com.google.common.collect.AbstractC3923f
    public final com.google.android.gms.internal.common.g j() {
        return a().listIterator(0);
    }

    @Override // com.google.common.collect.o
    public final j o() {
        return j.k(this.h, this.d);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return this.h;
    }

    @Override // com.google.common.collect.o, com.google.common.collect.AbstractC3923f
    public Object writeReplace() {
        return super.writeReplace();
    }
}
