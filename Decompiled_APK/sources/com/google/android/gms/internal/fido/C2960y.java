package com.google.android.gms.internal.fido;

import java.util.Iterator;

/* renamed from: com.google.android.gms.internal.fido.y, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2960y extends AbstractC2951o {
    public static final Object[] i;
    public static final C2960y j;
    public final transient Object[] d;
    public final transient int e;
    public final transient Object[] f;
    public final transient int g;
    public final transient int h;

    static {
        Object[] objArr = new Object[0];
        i = objArr;
        j = new C2960y(objArr, 0, objArr, 0, 0);
    }

    public C2960y(Object[] objArr, int i2, Object[] objArr2, int i3, int i4) {
        this.d = objArr;
        this.e = i2;
        this.f = objArr2;
        this.g = i3;
        this.h = i4;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final int a(Object[] objArr) {
        Object[] objArr2 = this.d;
        int i2 = this.h;
        System.arraycopy(objArr2, 0, objArr, 0, i2);
        return i2;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final int b() {
        return this.h;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final int c() {
        return 0;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        if (obj == null) {
            return false;
        }
        Object[] objArr = this.f;
        if (objArr.length == 0) {
            return false;
        }
        int iRotateLeft = (int) (Integer.rotateLeft((int) (obj.hashCode() * (-862048943)), 15) * 461845907);
        while (true) {
            int i2 = iRotateLeft & this.g;
            Object obj2 = objArr[i2];
            if (obj2 == null) {
                return false;
            }
            if (obj2.equals(obj)) {
                return true;
            }
            iRotateLeft = i2 + 1;
        }
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final D e() {
        return k().listIterator(0);
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final Object[] g() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2951o, java.util.Collection, java.util.Set
    public final int hashCode() {
        return this.e;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final /* synthetic */ Iterator iterator() {
        return k().listIterator(0);
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2951o
    public final AbstractC2949m m() {
        return AbstractC2949m.k(this.h, this.d);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return this.h;
    }
}
