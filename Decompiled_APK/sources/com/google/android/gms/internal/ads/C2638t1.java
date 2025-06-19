package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.t1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2638t1 implements InterfaceC2552r1 {
    public final long a;
    public final int b;
    public final long c;
    public final int d;
    public final long e;
    public final long f;
    public final long[] g;

    public C2638t1(long j, int i, long j2, int i2, long j3, long[] jArr) {
        this.a = j;
        this.b = i;
        this.c = j2;
        this.d = i2;
        this.e = j3;
        this.g = jArr;
        this.f = j3 != -1 ? j + j3 : -1L;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2552r1
    public final int a() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final C2078g0 b(long j) {
        double d;
        double d2;
        boolean zG = g();
        int i = this.b;
        long j2 = this.a;
        if (!zG) {
            C2166i0 c2166i0 = new C2166i0(0L, j2 + i);
            return new C2078g0(c2166i0, c2166i0);
        }
        String str = Yo.a;
        long j3 = this.c;
        long jMax = Math.max(0L, Math.min(j, j3));
        double d3 = (jMax * 100.0d) / j3;
        double d4 = 0.0d;
        if (d3 <= 0.0d) {
            d = 256.0d;
        } else if (d3 >= 100.0d) {
            d = 256.0d;
            d4 = 256.0d;
        } else {
            int i2 = (int) d3;
            long[] jArr = this.g;
            AbstractC1795We.p(jArr);
            double d5 = jArr[i2];
            if (i2 == 99) {
                d = 256.0d;
                d2 = 256.0d;
            } else {
                d = 256.0d;
                d2 = jArr[i2 + 1];
            }
            d4 = ((d2 - d5) * (d3 - i2)) + d5;
        }
        long j4 = this.e;
        C2166i0 c2166i02 = new C2166i0(jMax, Math.max(i, Math.min(Math.round((d4 / d) * j4), j4 - 1)) + j2);
        return new C2078g0(c2166i02, c2166i02);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2552r1
    public final long c(long j) {
        if (!g()) {
            return 0L;
        }
        long j2 = j - this.a;
        if (j2 <= this.b) {
            return 0L;
        }
        long[] jArr = this.g;
        AbstractC1795We.p(jArr);
        double d = (j2 * 256.0d) / this.e;
        int iK = Yo.k(jArr, (long) d, true);
        long j3 = this.c;
        long j4 = (iK * j3) / 100;
        long j5 = jArr[iK];
        int i = iK + 1;
        long j6 = (j3 * i) / 100;
        return Math.round((j5 == (iK == 99 ? 256L : jArr[i]) ? 0.0d : (d - j5) / (r0 - j5)) * (j6 - j4)) + j4;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final boolean g() {
        return this.g != null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2552r1
    public final long j() {
        return this.f;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final long zza() {
        return this.c;
    }
}
