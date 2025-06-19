package com.google.android.gms.internal.ads;

import androidx.compose.material3.C0591b1;
import java.util.Collections;

/* loaded from: classes2.dex */
public final class X2 implements N2 {
    public final String a;
    public final int b;
    public final Kn c;
    public final C2466p0 d;
    public InterfaceC2380n0 e;
    public String f;
    public C1832aG g;
    public int h;
    public int i;
    public int j;
    public int k;
    public long l;
    public boolean m;
    public int n;
    public int o;
    public int p;
    public boolean q;
    public long r;
    public int s;
    public long t;
    public int u;
    public String v;

    public X2(String str, int i) {
        this.a = str;
        this.b = i;
        Kn kn = new Kn(1024);
        this.c = kn;
        byte[] bArr = kn.a;
        this.d = new C2466p0(bArr.length, bArr);
        this.l = -9223372036854775807L;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void a(boolean z) {
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void d(Kn kn) throws zzaz {
        int iF;
        int i;
        int iF2;
        boolean zW;
        int i2;
        AbstractC1795We.p(this.e);
        while (kn.s() > 0) {
            int i3 = this.h;
            if (i3 != 0) {
                if (i3 != 1) {
                    C2466p0 c2466p0 = this.d;
                    Kn kn2 = this.c;
                    if (i3 != 2) {
                        int iMin = Math.min(kn.s(), this.j - this.i);
                        kn.f(this.i, c2466p0.b, iMin);
                        int i4 = this.i + iMin;
                        this.i = i4;
                        if (i4 == this.j) {
                            c2466p0.s(0);
                            if (c2466p0.w()) {
                                if (this.m) {
                                }
                                this.h = 0;
                            } else {
                                this.m = true;
                                int iF3 = c2466p0.f(1);
                                if (iF3 == 1) {
                                    iF2 = c2466p0.f(1);
                                    i = 1;
                                } else {
                                    i = iF3;
                                    iF2 = 0;
                                }
                                this.n = iF2;
                                if (iF2 != 0) {
                                    throw zzaz.a(null, null);
                                }
                                if (i == 1) {
                                    c2466p0.f((c2466p0.f(2) + 1) * 8);
                                    i = 1;
                                }
                                if (!c2466p0.w()) {
                                    throw zzaz.a(null, null);
                                }
                                this.o = c2466p0.f(6);
                                int iF4 = c2466p0.f(4);
                                int iF5 = c2466p0.f(3);
                                if (iF4 != 0 || iF5 != 0) {
                                    throw zzaz.a(null, null);
                                }
                                if (i == 0) {
                                    int i5 = (c2466p0.c * 8) + c2466p0.d;
                                    int iA = c2466p0.a();
                                    F fL = AbstractC2096gb.l(c2466p0, true);
                                    this.v = fL.a;
                                    this.s = fL.b;
                                    this.u = fL.c;
                                    int iA2 = iA - c2466p0.a();
                                    c2466p0.s(i5);
                                    byte[] bArr = new byte[(iA2 + 7) / 8];
                                    c2466p0.m(iA2, bArr);
                                    EF ef = new EF();
                                    ef.a = this.f;
                                    ef.a("video/mp2t");
                                    ef.d("audio/mp4a-latm");
                                    ef.i = this.v;
                                    ef.B = this.u;
                                    ef.C = this.s;
                                    ef.o = Collections.singletonList(bArr);
                                    ef.d = this.a;
                                    ef.f = this.b;
                                    C1832aG c1832aG = new C1832aG(ef);
                                    if (!c1832aG.equals(this.g)) {
                                        this.g = c1832aG;
                                        this.t = 1024000000 / c1832aG.D;
                                        this.e.a(c1832aG);
                                    }
                                } else {
                                    int iA3 = c2466p0.a();
                                    F fL2 = AbstractC2096gb.l(c2466p0, true);
                                    this.v = fL2.a;
                                    this.s = fL2.b;
                                    this.u = fL2.c;
                                    c2466p0.u(c2466p0.f((c2466p0.f(2) + 1) * 8) - (iA3 - c2466p0.a()));
                                }
                                int iF6 = c2466p0.f(3);
                                this.p = iF6;
                                if (iF6 == 0) {
                                    c2466p0.u(8);
                                } else if (iF6 == 1) {
                                    c2466p0.u(9);
                                } else if (iF6 == 3 || iF6 == 4 || iF6 == 5) {
                                    c2466p0.u(6);
                                } else {
                                    if (iF6 != 6 && iF6 != 7) {
                                        throw new IllegalStateException();
                                    }
                                    c2466p0.u(1);
                                }
                                boolean zW2 = c2466p0.w();
                                this.q = zW2;
                                this.r = 0L;
                                if (zW2) {
                                    if (i != 1) {
                                        do {
                                            zW = c2466p0.w();
                                            this.r = (this.r << 8) + c2466p0.f(8);
                                        } while (zW);
                                    } else {
                                        this.r = c2466p0.f((c2466p0.f(2) + 1) * 8);
                                    }
                                }
                                if (c2466p0.w()) {
                                    c2466p0.u(8);
                                }
                            }
                            if (this.n != 0) {
                                throw zzaz.a(null, null);
                            }
                            if (this.o != 0) {
                                throw zzaz.a(null, null);
                            }
                            if (this.p != 0) {
                                throw zzaz.a(null, null);
                            }
                            int i6 = 0;
                            do {
                                iF = c2466p0.f(8);
                                i6 += iF;
                            } while (iF == 255);
                            int i7 = (c2466p0.c * 8) + c2466p0.d;
                            if ((i7 & 7) == 0) {
                                kn2.j(i7 >> 3);
                            } else {
                                c2466p0.m(i6 * 8, kn2.a);
                                kn2.j(0);
                            }
                            this.e.e(i6, kn2);
                            AbstractC1795We.L(this.l != -9223372036854775807L);
                            this.e.f(this.l, 1, i6, 0, null);
                            this.l += this.t;
                            if (this.q) {
                                c2466p0.u((int) this.r);
                            }
                            this.h = 0;
                        } else {
                            continue;
                        }
                    } else {
                        int iZ = ((this.k & (-225)) << 8) | kn.z();
                        this.j = iZ;
                        if (iZ > kn2.a.length) {
                            kn2.g(iZ);
                            byte[] bArr2 = kn2.a;
                            int length = bArr2.length;
                            c2466p0.b = bArr2;
                            i2 = 0;
                            c2466p0.c = 0;
                            c2466p0.d = 0;
                            c2466p0.e = length;
                        } else {
                            i2 = 0;
                        }
                        this.i = i2;
                        this.h = 3;
                    }
                } else {
                    int iZ2 = kn.z();
                    if ((iZ2 & 224) == 224) {
                        this.k = iZ2;
                        this.h = 2;
                    } else if (iZ2 != 86) {
                        this.h = 0;
                    }
                }
            } else if (kn.z() == 86) {
                this.h = 1;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void e(W w, C0591b1 c0591b1) {
        c0591b1.b();
        c0591b1.c();
        this.e = w.q(c0591b1.c, 1);
        c0591b1.c();
        this.f = (String) c0591b1.e;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void f(int i, long j) {
        this.l = j;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void zze() {
        this.h = 0;
        this.l = -9223372036854775807L;
        this.m = false;
    }
}
