package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class GF implements InterfaceC2005eF, InterfaceC1962dF {
    public final InterfaceC2005eF a;
    public final long b;
    public InterfaceC1962dF c;

    public GF(InterfaceC2005eF interfaceC2005eF, long j) {
        this.a = interfaceC2005eF;
        this.b = j;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final long a() {
        long jA = this.a.a();
        if (jA == Long.MIN_VALUE) {
            return Long.MIN_VALUE;
        }
        return jA + this.b;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final long b() {
        long jB = this.a.b();
        if (jB == Long.MIN_VALUE) {
            return Long.MIN_VALUE;
        }
        return jB + this.b;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long c(long j) {
        InterfaceC2005eF interfaceC2005eF = this.a;
        long j2 = this.b;
        return interfaceC2005eF.c(j - j2) + j2;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final void d(long j) {
        this.a.d(j - this.b);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final void e(InterfaceC1962dF interfaceC1962dF, long j) {
        this.c = interfaceC1962dF;
        this.a.e(this, j - this.b);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long f(long j, OD od) {
        InterfaceC2005eF interfaceC2005eF = this.a;
        long j2 = this.b;
        return interfaceC2005eF.f(j - j2, od) + j2;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1962dF
    public final /* bridge */ /* synthetic */ void g(BF bf) {
        InterfaceC1962dF interfaceC1962dF = this.c;
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
        long j = this.a.j();
        if (j == -9223372036854775807L) {
            return -9223372036854775807L;
        }
        return j + this.b;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final boolean k(C2607sD c2607sD) {
        C2564rD c2564rD = new C2564rD();
        c2564rD.b = c2607sD.b;
        c2564rD.c = c2607sD.c;
        c2564rD.a = c2607sD.a - this.b;
        return this.a.k(new C2607sD(c2564rD));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1962dF
    public final void l(InterfaceC2005eF interfaceC2005eF) {
        InterfaceC1962dF interfaceC1962dF = this.c;
        interfaceC1962dF.getClass();
        interfaceC1962dF.l(this);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long m(XF[] xfArr, boolean[] zArr, AF[] afArr, boolean[] zArr2, long j) {
        AF[] afArr2 = new AF[afArr.length];
        int i = 0;
        while (true) {
            AF af = null;
            if (i >= afArr.length) {
                break;
            }
            FF ff = (FF) afArr[i];
            if (ff != null) {
                af = ff.a;
            }
            afArr2[i] = af;
            i++;
        }
        long j2 = this.b;
        long jM = this.a.m(xfArr, zArr, afArr2, zArr2, j - j2);
        for (int i2 = 0; i2 < afArr.length; i2++) {
            AF af2 = afArr2[i2];
            if (af2 == null) {
                afArr[i2] = null;
            } else {
                AF af3 = afArr[i2];
                if (af3 == null || ((FF) af3).a != af2) {
                    afArr[i2] = new FF(af2, j2);
                }
            }
        }
        return jM + j2;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final boolean o() {
        return this.a.o();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final void r(long j) {
        this.a.r(j - this.b);
    }
}
