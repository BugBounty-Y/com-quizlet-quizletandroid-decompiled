package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class PE implements InterfaceC2005eF, InterfaceC1962dF {
    public final ZE a;
    public InterfaceC1962dF b;
    public OE[] c = new OE[0];
    public long d = 0;
    public long e;

    public PE(ZE ze, long j) {
        this.a = ze;
        this.e = j;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final long a() {
        long jA = this.a.a();
        if (jA != Long.MIN_VALUE) {
            long j = this.e;
            if (j == Long.MIN_VALUE || jA < j) {
                return jA;
            }
        }
        return Long.MIN_VALUE;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final long b() {
        long jB = this.a.b();
        if (jB != Long.MIN_VALUE) {
            long j = this.e;
            if (j == Long.MIN_VALUE || jB < j) {
                return jB;
            }
        }
        return Long.MIN_VALUE;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long c(long j) {
        this.d = -9223372036854775807L;
        for (OE oe : this.c) {
            if (oe != null) {
                oe.b = false;
            }
        }
        long jC = this.a.c(j);
        long j2 = this.e;
        long jMax = Math.max(jC, 0L);
        return j2 != Long.MIN_VALUE ? Math.min(jMax, j2) : jMax;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final void d(long j) {
        this.a.d(j);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final void e(InterfaceC1962dF interfaceC1962dF, long j) {
        this.b = interfaceC1962dF;
        this.a.e(this, j);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long f(long j, OD od) {
        if (j == 0) {
            return 0L;
        }
        long j2 = od.a;
        String str = Yo.a;
        long jMax = Math.max(0L, Math.min(j2, j));
        long j3 = this.e;
        long j4 = j3 == Long.MIN_VALUE ? Long.MAX_VALUE : j3 - j;
        long j5 = od.b;
        long jMax2 = Math.max(0L, Math.min(j5, j4));
        if (jMax != j2 || jMax2 != j5) {
            od = new OD(jMax, jMax2);
        }
        return this.a.f(j, od);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1962dF
    public final /* bridge */ /* synthetic */ void g(BF bf) {
        InterfaceC1962dF interfaceC1962dF = this.b;
        interfaceC1962dF.getClass();
        interfaceC1962dF.g(this);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final HF h() {
        return this.a.h();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final void i() {
        this.a.i();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long j() {
        if (n()) {
            long j = this.d;
            this.d = -9223372036854775807L;
            long j2 = j();
            return j2 != -9223372036854775807L ? j2 : j;
        }
        long j3 = this.a.j();
        if (j3 == -9223372036854775807L) {
            return -9223372036854775807L;
        }
        long j4 = this.e;
        long jMax = Math.max(j3, 0L);
        return j4 != Long.MIN_VALUE ? Math.min(jMax, j4) : jMax;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final boolean k(C2607sD c2607sD) {
        return this.a.k(c2607sD);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1962dF
    public final void l(InterfaceC2005eF interfaceC2005eF) {
        InterfaceC1962dF interfaceC1962dF = this.b;
        interfaceC1962dF.getClass();
        interfaceC1962dF.l(this);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long m(XF[] xfArr, boolean[] zArr, AF[] afArr, boolean[] zArr2, long j) {
        int length = afArr.length;
        this.c = new OE[length];
        AF[] afArr2 = new AF[length];
        for (int i = 0; i < afArr.length; i++) {
            OE[] oeArr = this.c;
            OE oe = (OE) afArr[i];
            oeArr[i] = oe;
            afArr2[i] = oe != null ? oe.a : null;
        }
        long jM = this.a.m(xfArr, zArr, afArr2, zArr2, j);
        long j2 = this.e;
        long jMax = Math.max(jM, j);
        if (j2 != Long.MIN_VALUE) {
            jMax = Math.min(jMax, j2);
        }
        long j3 = -9223372036854775807L;
        if (n()) {
            if (jM < j) {
                j3 = jMax;
                break;
            }
            if (jM != 0) {
                for (XF xf : xfArr) {
                    if (xf != null) {
                        C1832aG c1832aGZzb = xf.zzb();
                        if (!AbstractC2514q5.f(c1832aGZzb.m, c1832aGZzb.j)) {
                            j3 = jMax;
                            break;
                        }
                    }
                }
            }
        }
        this.d = j3;
        for (int i2 = 0; i2 < afArr.length; i2++) {
            AF af = afArr2[i2];
            if (af == null) {
                this.c[i2] = null;
            } else {
                OE[] oeArr2 = this.c;
                OE oe2 = oeArr2[i2];
                if (oe2 == null || oe2.a != af) {
                    oeArr2[i2] = new OE(this, af);
                }
            }
            afArr[i2] = this.c[i2];
        }
        return jMax;
    }

    public final boolean n() {
        return this.d != -9223372036854775807L;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final boolean o() {
        return this.a.o();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final void r(long j) {
        this.a.r(j);
    }
}
