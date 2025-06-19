package com.google.android.gms.internal.ads;

import androidx.compose.material3.C0591b1;
import java.util.ArrayList;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class U2 implements N2 {
    public final C2326lq a;
    public long e;
    public String g;
    public InterfaceC2380n0 h;
    public T2 i;
    public boolean j;
    public boolean l;
    public final boolean[] f = new boolean[3];
    public final androidx.recyclerview.widget.N b = new androidx.recyclerview.widget.N(7);
    public final androidx.recyclerview.widget.N c = new androidx.recyclerview.widget.N(8);
    public final androidx.recyclerview.widget.N d = new androidx.recyclerview.widget.N(6);
    public long k = -9223372036854775807L;
    public final Kn m = new Kn();

    public U2(C2326lq c2326lq) {
        this.a = c2326lq;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void a(boolean z) {
        AbstractC1795We.p(this.h);
        String str = Yo.a;
        if (z) {
            ((androidx.navigation.internal.m) this.a.d).q(0);
            b(0, 0, this.e, this.k);
            c(this.e, this.k, 9);
            b(0, 0, this.e, this.k);
        }
    }

    public final void b(int i, int i2, long j, long j2) {
        boolean z = this.j;
        boolean z2 = true;
        androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) this.a.d;
        if (!z) {
            androidx.recyclerview.widget.N n = this.b;
            n.i(i2);
            androidx.recyclerview.widget.N n2 = this.c;
            n2.i(i2);
            if (this.j) {
                if (n.d) {
                    Js jsF = LA.F(4, (byte[]) n.f, n.e);
                    mVar.getClass();
                    int i3 = jsF.m;
                    AbstractC1795We.L(i3 >= 0);
                    mVar.c = i3;
                    mVar.q(i3);
                    this.i.b.append(jsF.d, jsF);
                    n.g();
                } else if (n2.d) {
                    C2466p0 c2466p0 = new C2466p0(4, (byte[]) n2.f, n2.e);
                    int iO = c2466p0.o();
                    c2466p0.o();
                    c2466p0.i();
                    c2466p0.n();
                    this.i.c.append(iO, new C2147hi(iO));
                    n2.g();
                }
            } else if (n.d && n2.d) {
                ArrayList arrayList = new ArrayList();
                arrayList.add(Arrays.copyOf((byte[]) n.f, n.e));
                arrayList.add(Arrays.copyOf((byte[]) n2.f, n2.e));
                Js jsF2 = LA.F(4, (byte[]) n.f, n.e);
                C2466p0 c2466p02 = new C2466p0(4, (byte[]) n2.f, n2.e);
                int iO2 = c2466p02.o();
                c2466p02.o();
                c2466p02.i();
                c2466p02.n();
                C2147hi c2147hi = new C2147hi(iO2);
                byte[] bArr = Hi.a;
                String str = String.format("avc1.%02X%02X%02X", Integer.valueOf(jsF2.a), Integer.valueOf(jsF2.b), Integer.valueOf(jsF2.c));
                InterfaceC2380n0 interfaceC2380n0 = this.h;
                EF ef = new EF();
                ef.a = this.g;
                ef.a("video/mp2t");
                ef.d("video/avc");
                ef.i = str;
                ef.s = jsF2.e;
                ef.t = jsF2.f;
                ef.z = new C2135hD(jsF2.j, jsF2.k, jsF2.l, jsF2.h + 8, jsF2.i + 8, null);
                ef.w = jsF2.g;
                ef.o = arrayList;
                int i4 = jsF2.m;
                ef.n = i4;
                interfaceC2380n0.a(new C1832aG(ef));
                this.j = true;
                mVar.getClass();
                AbstractC1795We.L(i4 >= 0);
                mVar.c = i4;
                mVar.q(i4);
                this.i.b.append(jsF2.d, jsF2);
                this.i.c.append(iO2, c2147hi);
                n.g();
                n2.g();
            }
        }
        androidx.recyclerview.widget.N n3 = this.d;
        if (n3.i(i2)) {
            int iU = LA.u(n3.e, (byte[]) n3.f);
            byte[] bArr2 = (byte[]) n3.f;
            Kn kn = this.m;
            kn.h(iU, bArr2);
            kn.j(4);
            mVar.p(j2, kn);
        }
        T2 t2 = this.i;
        boolean z3 = this.j;
        if (t2.d == 9) {
            if (z3 && t2.g) {
                long j3 = t2.e;
                int i5 = i + ((int) (j - j3));
                long j4 = t2.i;
                if (j4 != -9223372036854775807L) {
                    long j5 = t2.h;
                    if (j3 != j5) {
                        t2.a.f(j4, t2.j ? 1 : 0, (int) (j3 - j5), i5, null);
                    }
                }
            }
            t2.h = t2.e;
            t2.i = t2.f;
            t2.j = false;
            t2.g = true;
        }
        boolean z4 = t2.k;
        boolean z5 = t2.j;
        int i6 = t2.d;
        if (i6 != 5 && (!z4 || i6 != 1)) {
            z2 = false;
        }
        boolean z6 = z5 | z2;
        t2.j = z6;
        t2.d = 24;
        if (z6) {
            this.l = false;
        }
    }

    public final void c(long j, long j2, int i) {
        if (!this.j) {
            this.b.h(i);
            this.c.h(i);
        }
        this.d.h(i);
        T2 t2 = this.i;
        boolean z = this.l;
        t2.d = i;
        t2.f = j2;
        t2.e = j;
        t2.k = z;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0041  */
    @Override // com.google.android.gms.internal.ads.N2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(com.google.android.gms.internal.ads.Kn r14) {
        /*
            r13 = this;
            r7 = 3
            com.google.android.gms.internal.ads.n0 r2 = r13.h
            com.google.android.gms.internal.ads.AbstractC1795We.p(r2)
            java.lang.String r2 = com.google.android.gms.internal.ads.Yo.a
            int r2 = r14.b
            int r8 = r14.c
            byte[] r9 = r14.a
            long r3 = r13.e
            int r5 = r14.s()
            long r5 = (long) r5
            long r3 = r3 + r5
            r13.e = r3
            com.google.android.gms.internal.ads.n0 r3 = r13.h
            int r4 = r14.s()
            r3.e(r4, r14)
        L21:
            boolean[] r1 = r13.f
            int r1 = com.google.android.gms.internal.ads.LA.c(r9, r2, r8, r1)
            androidx.recyclerview.widget.N r3 = r13.d
            androidx.recyclerview.widget.N r4 = r13.c
            androidx.recyclerview.widget.N r5 = r13.b
            if (r1 == r8) goto L72
            int r6 = r1 + 3
            r6 = r9[r6]
            r10 = r6 & 31
            if (r1 <= 0) goto L41
            int r6 = r1 + (-1)
            r11 = r9[r6]
            if (r11 != 0) goto L41
            r1 = 4
            r12 = r1
            r11 = r6
            goto L43
        L41:
            r11 = r1
            r12 = r7
        L43:
            int r1 = r11 - r2
            if (r1 <= 0) goto L54
            boolean r6 = r13.j
            if (r6 != 0) goto L51
            r5.f(r2, r9, r11)
            r4.f(r2, r9, r11)
        L51:
            r3.f(r2, r9, r11)
        L54:
            int r2 = r8 - r11
            long r3 = r13.e
            long r5 = (long) r2
            long r3 = r3 - r5
            if (r1 >= 0) goto L5e
            int r1 = -r1
            goto L5f
        L5e:
            r1 = 0
        L5f:
            long r5 = r13.k
            r0 = r2
            r2 = r1
            r1 = r0
            r0 = r13
            r0.b(r1, r2, r3, r5)
            r1 = r3
            long r3 = r13.k
            r5 = r10
            r0.c(r1, r3, r5)
            int r2 = r11 + r12
            goto L21
        L72:
            boolean r1 = r13.j
            if (r1 != 0) goto L7c
            r5.f(r2, r9, r8)
            r4.f(r2, r9, r8)
        L7c:
            r3.f(r2, r9, r8)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.U2.d(com.google.android.gms.internal.ads.Kn):void");
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void e(W w, C0591b1 c0591b1) {
        c0591b1.b();
        c0591b1.c();
        this.g = (String) c0591b1.e;
        c0591b1.c();
        InterfaceC2380n0 interfaceC2380n0Q = w.q(c0591b1.c, 2);
        this.h = interfaceC2380n0Q;
        this.i = new T2(interfaceC2380n0Q);
        this.a.u(w, c0591b1);
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void f(int i, long j) {
        this.k = j;
        int i2 = i & 2;
        this.l = (i2 != 0) | this.l;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void zze() {
        this.e = 0L;
        this.l = false;
        this.k = -9223372036854775807L;
        LA.J(this.f);
        this.b.g();
        this.c.g();
        this.d.g();
        ((androidx.navigation.internal.m) this.a.d).q(0);
        T2 t2 = this.i;
        if (t2 != null) {
            t2.g = false;
        }
    }
}
