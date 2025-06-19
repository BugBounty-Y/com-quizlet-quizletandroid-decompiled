package com.google.android.gms.internal.ads;

import android.net.Uri;
import java.util.Collections;
import java.util.List;

/* loaded from: classes2.dex */
public final class DF extends A9 {
    public static final Object g = new Object();
    public final long b;
    public final long c;
    public final boolean d;
    public final C2640t3 e;
    public final D1 f;

    static {
        C2244ju c2244ju = AbstractC2330lu.b;
        Bu bu = Bu.e;
        List list = Collections.EMPTY_LIST;
        Bu bu2 = Bu.e;
        E2 e2 = E2.a;
        Uri uri = Uri.EMPTY;
        if (uri != null) {
            new V1(uri, bu2);
        }
        new I0();
        C2082g4 c2082g4 = C2082g4.B;
    }

    public DF(long j, long j2, boolean z, C2640t3 c2640t3, D1 d1) {
        this.b = j;
        this.c = j2;
        this.d = z;
        c2640t3.getClass();
        this.e = c2640t3;
        this.f = d1;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final int a(Object obj) {
        return g.equals(obj) ? 0 : -1;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final int b() {
        return 1;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final int c() {
        return 1;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final C2303l9 d(int i, C2303l9 c2303l9, boolean z) {
        AbstractC1795We.f(i, 1);
        Object obj = z ? g : null;
        P5 p5 = P5.b;
        c2303l9.b(null, obj, 0, this.b, false);
        return c2303l9;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final C2518q9 e(int i, C2518q9 c2518q9, long j) {
        AbstractC1795We.f(i, 1);
        Object obj = C2518q9.m;
        c2518q9.a(this.e, this.d, false, this.f, this.c);
        return c2518q9;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final Object f(int i) {
        AbstractC1795We.f(i, 1);
        return g;
    }
}
