package com.google.android.gms.internal.ads;

import android.os.Handler;
import android.os.Looper;

/* renamed from: com.google.android.gms.internal.ads.cF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1918cF extends TE {
    public final NE k;
    public final boolean l;
    public final C2518q9 m;
    public final C2303l9 n;
    public C1831aF o;
    public ZE p;
    public boolean q;
    public boolean r;
    public boolean s;

    public C1918cF(NE ne, boolean z) {
        boolean z2;
        this.k = ne;
        if (z) {
            ne.q();
            z2 = true;
        } else {
            z2 = false;
        }
        this.l = z2;
        this.m = new C2518q9();
        this.n = new C2303l9();
        ne.d();
        this.o = new C1831aF(new C1875bF(ne.c()), C2518q9.m, C1831aF.e);
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final void a(InterfaceC2005eF interfaceC2005eF) {
        ZE ze = (ZE) interfaceC2005eF;
        InterfaceC2005eF interfaceC2005eF2 = ze.d;
        if (interfaceC2005eF2 != null) {
            NE ne = ze.c;
            ne.getClass();
            ne.a(interfaceC2005eF2);
        }
        if (interfaceC2005eF == this.p) {
            this.p = null;
        }
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final C2640t3 c() {
        return this.k.c();
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final void d() {
        this.k.d();
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final void j(C2050fG c2050fG) {
        this.j = c2050fG;
        String str = Yo.a;
        Looper looperMyLooper = Looper.myLooper();
        AbstractC1795We.p(looperMyLooper);
        this.i = new Handler(looperMyLooper, null);
        if (this.l) {
            return;
        }
        this.q = true;
        t(null, this.k);
    }

    @Override // com.google.android.gms.internal.ads.TE, com.google.android.gms.internal.ads.NE
    public final void m() {
        this.r = false;
        this.q = false;
        super.m();
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final void p(C2640t3 c2640t3) {
        if (this.s) {
            C1831aF c1831aF = this.o;
            this.o = new C1831aF(new KD(this.o.b, c2640t3), c1831aF.c, c1831aF.d);
        } else {
            this.o = new C1831aF(new C1875bF(c2640t3), C2518q9.m, C1831aF.e);
        }
        this.k.p(c2640t3);
    }

    @Override // com.google.android.gms.internal.ads.NE
    public final void q() {
        this.k.q();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0068  */
    @Override // com.google.android.gms.internal.ads.TE
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void s(java.lang.Integer r9, com.google.android.gms.internal.ads.NE r10, com.google.android.gms.internal.ads.A9 r11) {
        /*
            r8 = this;
            java.lang.Void r9 = (java.lang.Void) r9
            boolean r9 = r8.r
            r10 = 0
            if (r9 == 0) goto L1f
            com.google.android.gms.internal.ads.aF r9 = r8.o
            com.google.android.gms.internal.ads.aF r0 = new com.google.android.gms.internal.ads.aF
            java.lang.Object r1 = r9.c
            java.lang.Object r9 = r9.d
            r0.<init>(r11, r1, r9)
            r8.o = r0
            com.google.android.gms.internal.ads.ZE r9 = r8.p
            if (r9 == 0) goto Lb7
            long r0 = r9.f
            r8.y(r0)
            goto Lb7
        L1f:
            boolean r9 = r11.o()
            if (r9 == 0) goto L43
            boolean r9 = r8.s
            if (r9 == 0) goto L35
            com.google.android.gms.internal.ads.aF r9 = r8.o
            com.google.android.gms.internal.ads.aF r0 = new com.google.android.gms.internal.ads.aF
            java.lang.Object r1 = r9.c
            java.lang.Object r9 = r9.d
            r0.<init>(r11, r1, r9)
            goto L3f
        L35:
            java.lang.Object r9 = com.google.android.gms.internal.ads.C2518q9.m
            java.lang.Object r0 = com.google.android.gms.internal.ads.C1831aF.e
            com.google.android.gms.internal.ads.aF r1 = new com.google.android.gms.internal.ads.aF
            r1.<init>(r11, r9, r0)
            r0 = r1
        L3f:
            r8.o = r0
            goto Lb7
        L43:
            r9 = 0
            com.google.android.gms.internal.ads.q9 r1 = r8.m
            r2 = 0
            r11.e(r9, r1, r2)
            java.lang.Object r6 = r1.a
            com.google.android.gms.internal.ads.ZE r0 = r8.p
            if (r0 == 0) goto L68
            com.google.android.gms.internal.ads.aF r4 = r8.o
            com.google.android.gms.internal.ads.gF r5 = r0.a
            java.lang.Object r5 = r5.a
            com.google.android.gms.internal.ads.l9 r7 = r8.n
            r4.n(r5, r7)
            com.google.android.gms.internal.ads.aF r4 = r8.o
            r4.e(r9, r1, r2)
            long r4 = r0.b
            int r9 = (r4 > r2 ? 1 : (r4 == r2 ? 0 : -1))
            if (r9 == 0) goto L68
            goto L69
        L68:
            r4 = r2
        L69:
            com.google.android.gms.internal.ads.l9 r2 = r8.n
            r3 = 0
            r0 = r11
            android.util.Pair r9 = r0.l(r1, r2, r3, r4)
            java.lang.Object r11 = r9.first
            java.lang.Object r9 = r9.second
            java.lang.Long r9 = (java.lang.Long) r9
            long r1 = r9.longValue()
            boolean r9 = r8.s
            if (r9 == 0) goto L8b
            com.google.android.gms.internal.ads.aF r9 = r8.o
            com.google.android.gms.internal.ads.aF r11 = new com.google.android.gms.internal.ads.aF
            java.lang.Object r3 = r9.c
            java.lang.Object r9 = r9.d
            r11.<init>(r0, r3, r9)
            goto L91
        L8b:
            com.google.android.gms.internal.ads.aF r9 = new com.google.android.gms.internal.ads.aF
            r9.<init>(r0, r6, r11)
            r11 = r9
        L91:
            r8.o = r11
            com.google.android.gms.internal.ads.ZE r9 = r8.p
            if (r9 == 0) goto Lb7
            boolean r11 = r8.y(r1)
            if (r11 == 0) goto Lb7
            com.google.android.gms.internal.ads.gF r9 = r9.a
            com.google.android.gms.internal.ads.aF r10 = r8.o
            java.lang.Object r10 = r10.d
            java.lang.Object r11 = r9.a
            if (r10 == 0) goto Lb3
            java.lang.Object r10 = com.google.android.gms.internal.ads.C1831aF.e
            boolean r10 = r11.equals(r10)
            if (r10 == 0) goto Lb3
            com.google.android.gms.internal.ads.aF r10 = r8.o
            java.lang.Object r11 = r10.d
        Lb3:
            com.google.android.gms.internal.ads.gF r10 = r9.a(r11)
        Lb7:
            r9 = 1
            r8.s = r9
            r8.r = r9
            com.google.android.gms.internal.ads.aF r9 = r8.o
            r8.k(r9)
            if (r10 == 0) goto Lcb
            com.google.android.gms.internal.ads.ZE r9 = r8.p
            r9.getClass()
            r9.n(r10)
        Lcb:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1918cF.s(java.lang.Integer, com.google.android.gms.internal.ads.NE, com.google.android.gms.internal.ads.A9):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.google.android.gms.internal.ads.TE
    public final /* bridge */ /* synthetic */ void u(Integer num) {
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.google.android.gms.internal.ads.TE
    public final /* synthetic */ void v(long j, Integer num) {
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.google.android.gms.internal.ads.TE
    public final C2093gF w(Integer num, C2093gF c2093gF) {
        Object obj = this.o.d;
        Object obj2 = c2093gF.a;
        if (obj != null && obj.equals(obj2)) {
            obj2 = C1831aF.e;
        }
        return c2093gF.a(obj2);
    }

    @Override // com.google.android.gms.internal.ads.NE
    /* renamed from: x, reason: merged with bridge method [inline-methods] */
    public final ZE b(C2093gF c2093gF, C1963dG c1963dG, long j) {
        ZE ze = new ZE(c2093gF, c1963dG, j);
        AbstractC1795We.L(ze.c == null);
        NE ne = this.k;
        ze.c = ne;
        if (!this.r) {
            this.p = ze;
            if (!this.q) {
                this.q = true;
                t(null, ne);
            }
            return ze;
        }
        Object obj = this.o.d;
        Object obj2 = c2093gF.a;
        if (obj != null && obj2.equals(C1831aF.e)) {
            obj2 = this.o.d;
        }
        ze.n(c2093gF.a(obj2));
        return ze;
    }

    public final boolean y(long j) {
        ZE ze = this.p;
        int iA = this.o.a(ze.a.a);
        if (iA == -1) {
            return false;
        }
        C1831aF c1831aF = this.o;
        C2303l9 c2303l9 = this.n;
        c1831aF.d(iA, c2303l9, false);
        long j2 = c2303l9.d;
        if (j2 != -9223372036854775807L && j >= j2) {
            j = Math.max(0L, j2 - 1);
        }
        ze.f = j;
        return true;
    }
}
