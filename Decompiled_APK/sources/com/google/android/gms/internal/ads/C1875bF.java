package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.bF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1875bF extends A9 {
    public final C2640t3 b;

    public C1875bF(C2640t3 c2640t3) {
        this.b = c2640t3;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final int a(Object obj) {
        return obj == C1831aF.e ? 0 : -1;
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
        Integer num = z ? 0 : null;
        Object obj = z ? C1831aF.e : null;
        P5 p5 = P5.b;
        c2303l9.b(num, obj, 0, -9223372036854775807L, true);
        return c2303l9;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final C2518q9 e(int i, C2518q9 c2518q9, long j) {
        Object obj = C2518q9.m;
        c2518q9.a(this.b, false, true, null, -9223372036854775807L);
        c2518q9.i = true;
        return c2518q9;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final Object f(int i) {
        return C1831aF.e;
    }
}
