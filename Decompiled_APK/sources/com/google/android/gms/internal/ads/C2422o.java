package com.google.android.gms.internal.ads;

import android.content.Context;
import android.util.Pair;
import android.view.Surface;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.o, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2422o implements E {
    public AbstractC2330lu a;
    public C1832aG b;
    public long c;
    public final /* synthetic */ C2593s d;

    public C2422o(C2593s c2593s, Context context) {
        this.d = c2593s;
        Yo.d(context);
        C2244ju c2244ju = AbstractC2330lu.b;
        this.a = Bu.e;
        this.c = -9223372036854775807L;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void B() {
        C2593s c2593s = this.d;
        if (c2593s.d) {
            c2593s.e.B();
        }
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void E(boolean z) {
        int i = 1;
        this.c = -9223372036854775807L;
        C2593s c2593s = this.d;
        if (c2593s.l == 1) {
            c2593s.k++;
            c2593s.e.E(z);
            while (c2593s.h.o() > 1) {
                c2593s.h.p();
            }
            if (c2593s.h.o() == 1) {
                ((r) c2593s.h.p()).getClass();
                C2244ju c2244ju = AbstractC2330lu.b;
                Bu bu = Bu.e;
                throw null;
            }
            c2593s.m = -9223372036854775807L;
            Bo bo = c2593s.i;
            AbstractC1795We.p(bo);
            bo.b(new RunnableC1989e(c2593s, i));
        }
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void G() {
        long j = this.c;
        C2593s c2593s = this.d;
        if (c2593s.m >= j) {
            c2593s.e.G();
        }
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void H(Surface surface, Pn pn) {
        C2593s c2593s = this.d;
        Pair pair = c2593s.j;
        if (pair != null && ((Surface) pair.first).equals(surface) && ((Pn) c2593s.j.second).equals(pn)) {
            return;
        }
        c2593s.j = Pair.create(surface, pn);
        pn.getClass();
    }

    @Override // com.google.android.gms.internal.ads.E
    public final boolean I(long j, C2207j c2207j) {
        AbstractC1795We.L(false);
        int i = this.d.n;
        if (i == -1 || i != 0) {
            return false;
        }
        throw null;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void J(long j, long j2) {
        this.d.e.J(j, j2);
    }

    @Override // com.google.android.gms.internal.ads.E
    public final boolean K() {
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0039  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0046  */
    @Override // com.google.android.gms.internal.ads.E
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean L(com.google.android.gms.internal.ads.C1832aG r9) throws com.google.android.gms.internal.ads.zzacg {
        /*
            r8 = this;
            com.google.android.gms.internal.ads.s r0 = r8.d
            int r1 = r0.l
            r2 = 0
            r3 = 1
            if (r1 != 0) goto La
            r1 = r3
            goto Lb
        La:
            r1 = r2
        Lb:
            com.google.android.gms.internal.ads.AbstractC1795We.L(r1)
            com.google.android.gms.internal.ads.hD r1 = r9.A
            if (r1 == 0) goto L18
            boolean r4 = r1.d()
            if (r4 != 0) goto L1a
        L18:
            com.google.android.gms.internal.ads.hD r1 = com.google.android.gms.internal.ads.C2135hD.h
        L1a:
            java.lang.String r4 = "EGL_EXT_gl_colorspace_bt2020_pq"
            r5 = 33
            r6 = 7
            int r1 = r1.c
            if (r1 != r6) goto L36
            int r1 = android.os.Build.VERSION.SDK_INT
            r7 = 34
            if (r1 >= r7) goto L35
            if (r1 < r5) goto L35
            boolean r1 = com.google.android.gms.internal.ads.AbstractC1972di.G(r4)
            if (r1 != 0) goto L32
            goto L35
        L32:
            com.google.android.gms.internal.ads.hD r1 = new com.google.android.gms.internal.ads.hD
            goto L74
        L35:
            r1 = r6
        L36:
            r7 = 6
            if (r1 != r7) goto L46
            int r6 = android.os.Build.VERSION.SDK_INT
            if (r6 < r5) goto L44
            boolean r4 = com.google.android.gms.internal.ads.AbstractC1972di.G(r4)
            if (r4 == 0) goto L44
            r2 = r3
        L44:
            r3 = r2
            goto L4e
        L46:
            if (r1 != r6) goto L4e
            java.lang.String r2 = "EGL_EXT_gl_colorspace_bt2020_hlg"
            boolean r3 = com.google.android.gms.internal.ads.AbstractC1972di.G(r2)
        L4e:
            if (r3 != 0) goto L74
            int r2 = android.os.Build.VERSION.SDK_INT
            r3 = 29
            if (r2 < r3) goto L74
            java.lang.String r2 = com.google.android.gms.internal.ads.Yo.a
            java.util.Locale r2 = java.util.Locale.US
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            java.lang.String r3 = "Color transfer "
            r2.<init>(r3)
            r2.append(r1)
            java.lang.String r1 = " is not supported. Falling back to OpenGl tone mapping."
            r2.append(r1)
            java.lang.String r1 = r2.toString()
            java.lang.String r2 = "PlaybackVidGraphWrapper"
            com.google.android.gms.internal.ads.AbstractC2096gb.J(r2, r1)
            com.google.android.gms.internal.ads.hD r1 = com.google.android.gms.internal.ads.C2135hD.h
        L74:
            android.os.Looper r1 = android.os.Looper.myLooper()
            com.google.android.gms.internal.ads.AbstractC1795We.p(r1)
            com.google.android.gms.internal.ads.ao r2 = r0.f
            r3 = 0
            com.google.android.gms.internal.ads.Bo r1 = r2.a(r1, r3)
            r0.i = r1
            com.google.android.gms.internal.ads.q r0 = r0.b     // Catch: com.google.android.gms.internal.ads.zzbw -> L8a
            r0.a()     // Catch: com.google.android.gms.internal.ads.zzbw -> L8a
            throw r3     // Catch: com.google.android.gms.internal.ads.zzbw -> L8a
        L8a:
            r0 = move-exception
            com.google.android.gms.internal.ads.zzacg r1 = new com.google.android.gms.internal.ads.zzacg
            r1.<init>(r0, r9)
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2422o.L(com.google.android.gms.internal.ads.aG):boolean");
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void M(float f) {
        this.d.e.M(f);
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void N(boolean z) {
        C2593s c2593s = this.d;
        if (c2593s.d) {
            c2593s.e.N(z);
        }
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void O(InterfaceC2636t interfaceC2636t) {
        this.d.e.j = interfaceC2636t;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void P(C1832aG c1832aG, long j, int i, List list) {
        AbstractC1795We.L(false);
        this.a = AbstractC2330lu.n(list);
        this.b = c1832aG;
        EF ef = new EF(c1832aG);
        C2135hD c2135hD = c1832aG.A;
        if (c2135hD == null || !c2135hD.d()) {
            c2135hD = C2135hD.h;
        }
        ef.z = c2135hD;
        ef.e();
        throw null;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void Q() {
        C2593s c2593s = this.d;
        if (c2593s.d) {
            c2593s.e.Q();
        }
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void R(int i) {
        this.d.e.R(i);
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void S(Ts ts) {
    }

    @Override // com.google.android.gms.internal.ads.E
    public final boolean T() {
        return false;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final boolean U(boolean z) {
        return this.d.e.a.h(false);
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void V(long j) {
        this.d.e.g = j;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void W(List list) {
        if (this.a.equals(list)) {
            return;
        }
        this.a = AbstractC2330lu.n(list);
        C1832aG c1832aG = this.b;
        if (c1832aG == null) {
            return;
        }
        EF ef = new EF(c1832aG);
        C2135hD c2135hD = c1832aG.A;
        if (c2135hD == null || !c2135hD.d()) {
            c2135hD = C2135hD.h;
        }
        ef.z = c2135hD;
        ef.e();
        throw null;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void g() {
        C2593s c2593s = this.d;
        if (c2593s.h.o() == 0) {
            c2593s.e.g();
            return;
        }
        androidx.compose.ui.text.android.selection.f fVar = new androidx.compose.ui.text.android.selection.f(4, (byte) 0);
        if (c2593s.h.o() <= 0) {
            c2593s.h = fVar;
        } else {
            ((r) c2593s.h.p()).getClass();
            throw null;
        }
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void l() {
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void m() {
        C2593s c2593s = this.d;
        if (c2593s.l == 2) {
            return;
        }
        Bo bo = c2593s.i;
        if (bo != null) {
            bo.a.removeCallbacksAndMessages(null);
        }
        c2593s.j = null;
        c2593s.l = 2;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final Surface zzb() {
        AbstractC1795We.L(false);
        throw null;
    }

    @Override // com.google.android.gms.internal.ads.E
    public final void zzi() {
        C2593s c2593s = this.d;
        c2593s.getClass();
        Pn.c.getClass();
        c2593s.j = null;
    }
}
