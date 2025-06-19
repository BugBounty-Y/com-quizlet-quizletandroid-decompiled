package com.google.android.gms.internal.ads;

import androidx.compose.material3.C0591b1;

/* loaded from: classes2.dex */
public final class Y2 implements N2 {
    public final Kn a;
    public final C2034f0 b;
    public final String c;
    public final int d;
    public final String e;
    public InterfaceC2380n0 f;
    public String g;
    public int h = 0;
    public int i;
    public boolean j;
    public boolean k;
    public long l;
    public int m;
    public long n;

    public Y2(String str, int i, String str2) {
        Kn kn = new Kn(4);
        this.a = kn;
        kn.a[0] = -1;
        this.b = new C2034f0();
        this.n = -9223372036854775807L;
        this.c = str;
        this.d = i;
        this.e = str2;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void a(boolean z) {
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void d(Kn kn) {
        AbstractC1795We.p(this.f);
        while (kn.s() > 0) {
            int i = this.h;
            Kn kn2 = this.a;
            if (i == 0) {
                byte[] bArr = kn.a;
                int i2 = kn.b;
                int i3 = kn.c;
                while (true) {
                    if (i2 >= i3) {
                        kn.j(i3);
                        break;
                    }
                    int i4 = i2 + 1;
                    byte b = bArr[i2];
                    boolean z = (b & 255) == 255;
                    boolean z2 = this.k && (b & 224) == 224;
                    this.k = z;
                    if (z2) {
                        kn.j(i4);
                        this.k = false;
                        kn2.a[1] = bArr[i2];
                        this.i = 2;
                        this.h = 1;
                        break;
                    }
                    i2 = i4;
                }
            } else if (i != 1) {
                int iMin = Math.min(kn.s(), this.m - this.i);
                this.f.e(iMin, kn);
                int i5 = this.i + iMin;
                this.i = i5;
                if (i5 >= this.m) {
                    AbstractC1795We.L(this.n != -9223372036854775807L);
                    this.f.f(this.n, 1, this.m, 0, null);
                    this.n += this.l;
                    this.i = 0;
                    this.h = 0;
                }
            } else {
                int iMin2 = Math.min(kn.s(), 4 - this.i);
                kn.f(this.i, kn2.a, iMin2);
                int i6 = this.i + iMin2;
                this.i = i6;
                if (i6 >= 4) {
                    kn2.j(0);
                    int iU = kn2.u();
                    C2034f0 c2034f0 = this.b;
                    if (c2034f0.a(iU)) {
                        this.m = c2034f0.b;
                        if (!this.j) {
                            this.l = (c2034f0.g * 1000000) / c2034f0.c;
                            EF ef = new EF();
                            ef.a = this.g;
                            ef.a(this.e);
                            ef.d((String) c2034f0.e);
                            ef.m = 4096;
                            ef.B = c2034f0.d;
                            ef.C = c2034f0.c;
                            ef.d = this.c;
                            ef.f = this.d;
                            this.f.a(new C1832aG(ef));
                            this.j = true;
                        }
                        kn2.j(0);
                        this.f.e(4, kn2);
                        this.h = 2;
                    } else {
                        this.i = 0;
                        this.h = 1;
                    }
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void e(W w, C0591b1 c0591b1) {
        c0591b1.b();
        c0591b1.c();
        this.g = (String) c0591b1.e;
        c0591b1.c();
        this.f = w.q(c0591b1.c, 1);
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void f(int i, long j) {
        this.n = j;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void zze() {
        this.h = 0;
        this.i = 0;
        this.k = false;
        this.n = -9223372036854775807L;
    }
}
