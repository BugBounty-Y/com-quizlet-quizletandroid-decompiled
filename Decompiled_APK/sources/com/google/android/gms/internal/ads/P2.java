package com.google.android.gms.internal.ads;

import androidx.compose.material3.C0591b1;

/* loaded from: classes2.dex */
public final class P2 implements N2 {
    public static final double[] r = {23.976023976023978d, 24.0d, 25.0d, 29.97002997002997d, 30.0d, 50.0d, 59.94005994005994d, 60.0d};
    public String a;
    public InterfaceC2380n0 b;
    public final Fi c;
    public final String d;
    public final Kn e;
    public final androidx.recyclerview.widget.N f;
    public final boolean[] g = new boolean[4];
    public final O2 h;
    public long i;
    public boolean j;
    public boolean k;
    public long l;
    public long m;
    public long n;
    public long o;
    public boolean p;
    public boolean q;

    public P2(Fi fi, String str) {
        Kn kn;
        this.c = fi;
        this.d = str;
        O2 o2 = new O2();
        o2.d = new byte[128];
        this.h = o2;
        if (fi != null) {
            this.f = new androidx.recyclerview.widget.N(178);
            kn = new Kn();
        } else {
            kn = null;
            this.f = null;
        }
        this.e = kn;
        this.m = -9223372036854775807L;
        this.o = -9223372036854775807L;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void a(boolean z) {
        AbstractC1795We.p(this.b);
        if (z) {
            boolean z2 = this.p;
            long j = this.i - this.n;
            this.b.f(this.o, z2 ? 1 : 0, (int) j, 0, null);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:65:0x019c  */
    @Override // com.google.android.gms.internal.ads.N2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(com.google.android.gms.internal.ads.Kn r29) {
        /*
            Method dump skipped, instructions count: 533
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.P2.d(com.google.android.gms.internal.ads.Kn):void");
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void e(W w, C0591b1 c0591b1) {
        c0591b1.b();
        c0591b1.c();
        this.a = (String) c0591b1.e;
        c0591b1.c();
        this.b = w.q(c0591b1.c, 2);
        Fi fi = this.c;
        if (fi != null) {
            fi.n(w, c0591b1);
        }
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void f(int i, long j) {
        this.m = j;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void zze() {
        LA.J(this.g);
        O2 o2 = this.h;
        o2.a = false;
        o2.b = 0;
        o2.c = 0;
        androidx.recyclerview.widget.N n = this.f;
        if (n != null) {
            n.g();
        }
        this.i = 0L;
        this.j = false;
        this.m = -9223372036854775807L;
        this.o = -9223372036854775807L;
    }
}
