package com.google.android.gms.internal.fido;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.fido.x, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2959x extends AbstractC2949m {
    public static final C2959x e = new C2959x(new Object[0], 0);
    public final transient Object[] c;
    public final transient int d;

    public C2959x(Object[] objArr, int i) {
        this.c = objArr;
        this.d = i;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2949m, com.google.android.gms.internal.fido.AbstractC2944h
    public final int a(Object[] objArr) {
        Object[] objArr2 = this.c;
        int i = this.d;
        System.arraycopy(objArr2, 0, objArr, 0, i);
        return i;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final int b() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final int c() {
        return 0;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final Object[] g() {
        return this.c;
    }

    @Override // java.util.List
    public final Object get(int i) {
        AbstractC2937a.e(i, this.d);
        Object obj = this.c[i];
        Objects.requireNonNull(obj);
        return obj;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.d;
    }
}
