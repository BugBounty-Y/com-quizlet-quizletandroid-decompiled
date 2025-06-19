package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.o5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2428o5 extends AbstractCallableC2599s5 {
    public final boolean h;

    public C2428o5(Z4 z4, C1864b4 c1864b4, int i) {
        super(z4, "jIv42z2v6FXxayFh75bTXtsxRSsCK/ciQjkFKmgks8cLq7HP+HDebRZyGvyOBC97", "2wHbvH170oRSgA6rj2BMxMfMsZs+WbUtizDquheRwWE=", c1864b4, i, 61);
        this.h = z4.o.a;
    }

    @Override // com.google.android.gms.internal.ads.AbstractCallableC2599s5
    public final void a() {
        long jLongValue = ((Long) this.e.invoke(null, this.a.a, Boolean.valueOf(this.h))).longValue();
        C1864b4 c1864b4 = this.d;
        synchronized (c1864b4) {
            c1864b4.e();
            C2384n4.F((C2384n4) c1864b4.b, jLongValue);
        }
    }
}
