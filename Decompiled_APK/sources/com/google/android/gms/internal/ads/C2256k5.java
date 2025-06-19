package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.k5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2256k5 extends AbstractCallableC2599s5 {
    public final long h;

    public C2256k5(Z4 z4, C1864b4 c1864b4, long j, int i) {
        super(z4, "bz3lIaHWpCquphICM8d57wBZcB7vA3QBLpLSSF22FzCVTv7HI8nqsTojeybBUatg", "nJy2u10FH1OsIt1ONuXNmQ7d3Q3+he826LogUVDBAds=", c1864b4, i, 25);
        this.h = j;
    }

    @Override // com.google.android.gms.internal.ads.AbstractCallableC2599s5
    public final void a() {
        long jLongValue = ((Long) this.e.invoke(null, null)).longValue();
        C1864b4 c1864b4 = this.d;
        synchronized (c1864b4) {
            c1864b4.e();
            C2384n4.F0((C2384n4) c1864b4.b, jLongValue);
            long j = this.h;
            if (j != 0) {
                c1864b4.e();
                C2384n4.U((C2384n4) c1864b4.b, jLongValue - j);
                c1864b4.e();
                C2384n4.V((C2384n4) c1864b4.b, j);
            }
        }
    }
}
