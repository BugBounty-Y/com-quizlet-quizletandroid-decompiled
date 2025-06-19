package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public class Y implements InterfaceC2122h0 {
    public final /* synthetic */ int a;
    public final long b;
    public final Object c;

    public /* synthetic */ Y(Object obj, long j, int i) {
        this.a = i;
        this.c = obj;
        this.b = j;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final C2078g0 b(long j) {
        Object obj = this.c;
        switch (this.a) {
            case 0:
                Z z = (Z) obj;
                Fi fi = z.k;
                AbstractC1795We.p(fi);
                String str = Yo.a;
                long jMax = Math.max(0L, Math.min((z.e * j) / 1000000, z.j - 1));
                long[] jArr = (long[]) fi.b;
                int iK = Yo.k(jArr, jMax, false);
                long j2 = iK == -1 ? 0L : jArr[iK];
                long[] jArr2 = (long[]) fi.c;
                long j3 = iK != -1 ? jArr2[iK] : 0L;
                int i = z.e;
                long j4 = (j2 * 1000000) / i;
                long j5 = this.b;
                C2166i0 c2166i0 = new C2166i0(j4, j3 + j5);
                if (j4 == j || iK == jArr.length - 1) {
                    return new C2078g0(c2166i0, c2166i0);
                }
                int i2 = iK + 1;
                return new C2078g0(c2166i0, new C2166i0((jArr[i2] * 1000000) / i, j5 + jArr2[i2]));
            case 1:
                return (C2078g0) obj;
            default:
                C2637t0 c2637t0 = (C2637t0) obj;
                C2078g0 c2078g0A = c2637t0.i[0].a(j);
                int i3 = 1;
                while (true) {
                    C2766w0[] c2766w0Arr = c2637t0.i;
                    if (i3 >= c2766w0Arr.length) {
                        return c2078g0A;
                    }
                    C2078g0 c2078g0A2 = c2766w0Arr[i3].a(j);
                    if (c2078g0A2.a.b < c2078g0A.a.b) {
                        c2078g0A = c2078g0A2;
                    }
                    i3++;
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final boolean g() {
        switch (this.a) {
            case 0:
                return true;
            case 1:
                return false;
            default:
                return true;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final long zza() {
        switch (this.a) {
        }
        return this.b;
    }

    public Y(long j, long j2) {
        this.a = 1;
        this.b = j;
        C2166i0 c2166i0 = j2 == 0 ? C2166i0.c : new C2166i0(0L, j2);
        this.c = new C2078g0(c2166i0, c2166i0);
    }
}
