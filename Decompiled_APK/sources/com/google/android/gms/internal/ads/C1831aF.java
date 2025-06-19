package com.google.android.gms.internal.ads;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.aF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1831aF extends WE {
    public static final Object e = new Object();
    public final Object c;
    public final Object d;

    public C1831aF(A9 a9, Object obj, Object obj2) {
        super(a9);
        this.c = obj;
        this.d = obj2;
    }

    @Override // com.google.android.gms.internal.ads.WE, com.google.android.gms.internal.ads.A9
    public final int a(Object obj) {
        Object obj2;
        if (e.equals(obj) && (obj2 = this.d) != null) {
            obj = obj2;
        }
        return this.b.a(obj);
    }

    @Override // com.google.android.gms.internal.ads.WE, com.google.android.gms.internal.ads.A9
    public final C2303l9 d(int i, C2303l9 c2303l9, boolean z) {
        this.b.d(i, c2303l9, z);
        if (Objects.equals(c2303l9.b, this.d) && z) {
            c2303l9.b = e;
        }
        return c2303l9;
    }

    @Override // com.google.android.gms.internal.ads.WE, com.google.android.gms.internal.ads.A9
    public final C2518q9 e(int i, C2518q9 c2518q9, long j) {
        this.b.e(i, c2518q9, j);
        if (Objects.equals(c2518q9.a, this.c)) {
            c2518q9.a = C2518q9.m;
        }
        return c2518q9;
    }

    @Override // com.google.android.gms.internal.ads.WE, com.google.android.gms.internal.ads.A9
    public final Object f(int i) {
        Object objF = this.b.f(i);
        return Objects.equals(objF, this.d) ? e : objF;
    }
}
