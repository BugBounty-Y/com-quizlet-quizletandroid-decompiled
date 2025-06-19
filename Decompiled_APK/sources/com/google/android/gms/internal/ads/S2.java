package com.google.android.gms.internal.ads;

import androidx.compose.material3.C0591b1;

/* loaded from: classes2.dex */
public final class S2 implements N2 {
    public static final float[] l = {1.0f, 1.0f, 1.0909091f, 0.90909094f, 1.4545455f, 1.2121212f, 1.0f};
    public final Fi a;
    public final Kn b;
    public final boolean[] c = new boolean[4];
    public final Q2 d;
    public final androidx.recyclerview.widget.N e;
    public R2 f;
    public long g;
    public String h;
    public InterfaceC2380n0 i;
    public boolean j;
    public long k;

    public S2(Fi fi) {
        this.a = fi;
        Q2 q2 = new Q2();
        q2.e = new byte[128];
        this.d = q2;
        this.k = -9223372036854775807L;
        this.e = new androidx.recyclerview.widget.N(178);
        this.b = new Kn();
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void a(boolean z) {
        AbstractC1795We.p(this.f);
        if (z) {
            this.f.b(this.j, this.g, 0);
            R2 r2 = this.f;
            r2.b = false;
            r2.c = false;
            r2.d = false;
            r2.e = -1;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x0252  */
    /* JADX WARN: Removed duplicated region for block: B:102:0x0254  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00e7  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0122  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0139  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x01ed  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x01f2  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x01f9  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0219  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x0229  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x0246  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x024b A[PHI: r13
  0x024b: PHI (r13v2 int) = (r13v1 int), (r13v4 int) binds: [B:93:0x0244, B:96:0x024a] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // com.google.android.gms.internal.ads.N2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(com.google.android.gms.internal.ads.Kn r22) {
        /*
            Method dump skipped, instructions count: 610
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.S2.d(com.google.android.gms.internal.ads.Kn):void");
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void e(W w, C0591b1 c0591b1) {
        c0591b1.b();
        c0591b1.c();
        this.h = (String) c0591b1.e;
        c0591b1.c();
        InterfaceC2380n0 interfaceC2380n0Q = w.q(c0591b1.c, 2);
        this.i = interfaceC2380n0Q;
        this.f = new R2(interfaceC2380n0Q);
        this.a.n(w, c0591b1);
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void f(int i, long j) {
        this.k = j;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void zze() {
        LA.J(this.c);
        Q2 q2 = this.d;
        q2.a = false;
        q2.c = 0;
        q2.b = 0;
        R2 r2 = this.f;
        if (r2 != null) {
            r2.b = false;
            r2.c = false;
            r2.d = false;
            r2.e = -1;
        }
        this.e.g();
        this.g = 0L;
        this.k = -9223372036854775807L;
    }
}
