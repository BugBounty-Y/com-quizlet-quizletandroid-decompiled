package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class ZE implements InterfaceC2005eF, InterfaceC1962dF {
    public final C2093gF a;
    public final long b;
    public NE c;
    public InterfaceC2005eF d;
    public InterfaceC1962dF e;
    public long f = -9223372036854775807L;
    public final C1963dG g;

    public ZE(C2093gF c2093gF, C1963dG c1963dG, long j) {
        this.a = c2093gF;
        this.g = c1963dG;
        this.b = j;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final long a() {
        InterfaceC2005eF interfaceC2005eF = this.d;
        String str = Yo.a;
        return interfaceC2005eF.a();
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final long b() {
        InterfaceC2005eF interfaceC2005eF = this.d;
        String str = Yo.a;
        return interfaceC2005eF.b();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long c(long j) {
        InterfaceC2005eF interfaceC2005eF = this.d;
        String str = Yo.a;
        return interfaceC2005eF.c(j);
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final void d(long j) {
        InterfaceC2005eF interfaceC2005eF = this.d;
        String str = Yo.a;
        interfaceC2005eF.d(j);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final void e(InterfaceC1962dF interfaceC1962dF, long j) {
        this.e = interfaceC1962dF;
        InterfaceC2005eF interfaceC2005eF = this.d;
        if (interfaceC2005eF != null) {
            long j2 = this.f;
            if (j2 == -9223372036854775807L) {
                j2 = this.b;
            }
            interfaceC2005eF.e(this, j2);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long f(long j, OD od) {
        InterfaceC2005eF interfaceC2005eF = this.d;
        String str = Yo.a;
        return interfaceC2005eF.f(j, od);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1962dF
    public final /* bridge */ /* synthetic */ void g(BF bf) {
        InterfaceC1962dF interfaceC1962dF = this.e;
        String str = Yo.a;
        interfaceC1962dF.g(this);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final HF h() {
        InterfaceC2005eF interfaceC2005eF = this.d;
        String str = Yo.a;
        return interfaceC2005eF.h();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final void i() {
        InterfaceC2005eF interfaceC2005eF = this.d;
        if (interfaceC2005eF != null) {
            interfaceC2005eF.i();
            return;
        }
        NE ne = this.c;
        if (ne != null) {
            ne.r();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long j() {
        InterfaceC2005eF interfaceC2005eF = this.d;
        String str = Yo.a;
        return interfaceC2005eF.j();
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final boolean k(C2607sD c2607sD) {
        InterfaceC2005eF interfaceC2005eF = this.d;
        return interfaceC2005eF != null && interfaceC2005eF.k(c2607sD);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1962dF
    public final void l(InterfaceC2005eF interfaceC2005eF) {
        InterfaceC1962dF interfaceC1962dF = this.e;
        String str = Yo.a;
        interfaceC1962dF.l(this);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long m(XF[] xfArr, boolean[] zArr, AF[] afArr, boolean[] zArr2, long j) {
        long j2 = this.f;
        long j3 = (j2 == -9223372036854775807L || j != this.b) ? j : j2;
        this.f = -9223372036854775807L;
        InterfaceC2005eF interfaceC2005eF = this.d;
        String str = Yo.a;
        return interfaceC2005eF.m(xfArr, zArr, afArr, zArr2, j3);
    }

    public final void n(C2093gF c2093gF) {
        long j = this.f;
        if (j == -9223372036854775807L) {
            j = this.b;
        }
        NE ne = this.c;
        ne.getClass();
        InterfaceC2005eF interfaceC2005eFB = ne.b(c2093gF, this.g, j);
        this.d = interfaceC2005eFB;
        if (this.e != null) {
            interfaceC2005eFB.e(this, j);
        }
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final boolean o() {
        InterfaceC2005eF interfaceC2005eF = this.d;
        return interfaceC2005eF != null && interfaceC2005eF.o();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final void r(long j) {
        InterfaceC2005eF interfaceC2005eF = this.d;
        String str = Yo.a;
        interfaceC2005eF.r(j);
    }
}
