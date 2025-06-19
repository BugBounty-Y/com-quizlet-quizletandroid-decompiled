package com.google.android.gms.internal.ads;

import androidx.compose.material3.C0591b1;
import java.util.Collections;

/* loaded from: classes2.dex */
public final class W2 implements N2 {
    public final C2326lq a;
    public String b;
    public InterfaceC2380n0 c;
    public V2 d;
    public boolean e;
    public long l;
    public final boolean[] f = new boolean[3];
    public final androidx.recyclerview.widget.N g = new androidx.recyclerview.widget.N(32);
    public final androidx.recyclerview.widget.N h = new androidx.recyclerview.widget.N(33);
    public final androidx.recyclerview.widget.N i = new androidx.recyclerview.widget.N(34);
    public final androidx.recyclerview.widget.N j = new androidx.recyclerview.widget.N(39);
    public final androidx.recyclerview.widget.N k = new androidx.recyclerview.widget.N(40);
    public long m = -9223372036854775807L;
    public final Kn n = new Kn();

    public W2(C2326lq c2326lq) {
        this.a = c2326lq;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void a(boolean z) {
        AbstractC1795We.p(this.c);
        String str = Yo.a;
        if (z) {
            ((androidx.navigation.internal.m) this.a.d).q(0);
            b(0, 0, this.l, this.m);
            g(0, 48, this.l, this.m);
        }
    }

    public final void b(int i, int i2, long j, long j2) {
        V2 v2 = this.d;
        boolean z = this.e;
        if (v2.j && v2.g) {
            v2.m = v2.c;
            v2.j = false;
        } else if (v2.h || v2.g) {
            if (z && v2.i) {
                v2.a(i + ((int) (j - v2.b)));
            }
            v2.k = v2.b;
            v2.l = v2.e;
            v2.m = v2.c;
            v2.i = true;
        }
        boolean z2 = this.e;
        androidx.navigation.internal.m mVar = (androidx.navigation.internal.m) this.a.d;
        if (!z2) {
            androidx.recyclerview.widget.N n = this.g;
            n.i(i2);
            androidx.recyclerview.widget.N n2 = this.h;
            n2.i(i2);
            androidx.recyclerview.widget.N n3 = this.i;
            n3.i(i2);
            if (n.d && n2.d && n3.d) {
                String str = this.b;
                int i3 = n.e;
                byte[] bArr = new byte[n2.e + i3 + n3.e];
                System.arraycopy((byte[]) n.f, 0, bArr, 0, i3);
                System.arraycopy((byte[]) n2.f, 0, bArr, n.e, n2.e);
                System.arraycopy((byte[]) n3.f, 0, bArr, n.e + n2.e, n3.e);
                Tr trX = LA.x((byte[]) n2.f, 3, n2.e, null);
                Oq oq = trX.b;
                String strC = oq != null ? Hi.c(oq.a, oq.b, oq.c, oq.d, oq.e, oq.f) : null;
                EF ef = new EF();
                ef.a = str;
                ef.a("video/mp2t");
                ef.d("video/hevc");
                ef.i = strC;
                ef.s = trX.e;
                ef.t = trX.f;
                ef.z = new C2135hD(trX.i, trX.j, trX.k, trX.c + 8, trX.d + 8, null);
                ef.w = trX.g;
                ef.n = trX.h;
                ef.A = trX.a + 1;
                ef.o = Collections.singletonList(bArr);
                C1832aG c1832aG = new C1832aG(ef);
                this.c.a(c1832aG);
                int i4 = c1832aG.o;
                if (i4 == -1) {
                    throw new IllegalStateException();
                }
                mVar.getClass();
                AbstractC1795We.L(i4 >= 0);
                mVar.c = i4;
                mVar.q(i4);
                this.e = true;
            }
        }
        androidx.recyclerview.widget.N n4 = this.j;
        boolean zI = n4.i(i2);
        Kn kn = this.n;
        if (zI) {
            kn.h(LA.u(n4.e, (byte[]) n4.f), (byte[]) n4.f);
            kn.k(5);
            mVar.p(j2, kn);
        }
        androidx.recyclerview.widget.N n5 = this.k;
        if (n5.i(i2)) {
            kn.h(LA.u(n5.e, (byte[]) n5.f), (byte[]) n5.f);
            kn.k(5);
            mVar.p(j2, kn);
        }
    }

    public final void c(int i, byte[] bArr, int i2) {
        V2 v2 = this.d;
        if (v2.f) {
            int i3 = v2.d;
            int i4 = (i + 2) - i3;
            if (i4 < i2) {
                v2.g = (bArr[i4] & 128) != 0;
                v2.f = false;
            } else {
                v2.d = (i2 - i) + i3;
            }
        }
        if (!this.e) {
            this.g.f(i, bArr, i2);
            this.h.f(i, bArr, i2);
            this.i.f(i, bArr, i2);
        }
        this.j.f(i, bArr, i2);
        this.k.f(i, bArr, i2);
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0045  */
    @Override // com.google.android.gms.internal.ads.N2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(com.google.android.gms.internal.ads.Kn r16) {
        /*
            r15 = this;
            r7 = r16
            r8 = 3
            com.google.android.gms.internal.ads.n0 r1 = r15.c
            com.google.android.gms.internal.ads.AbstractC1795We.p(r1)
            java.lang.String r1 = com.google.android.gms.internal.ads.Yo.a
        La:
            int r1 = r7.s()
            if (r1 <= 0) goto L6e
            int r1 = r7.b
            int r9 = r7.c
            byte[] r10 = r7.a
            long r2 = r15.l
            int r4 = r7.s()
            long r4 = (long) r4
            long r2 = r2 + r4
            r15.l = r2
            com.google.android.gms.internal.ads.n0 r2 = r15.c
            int r3 = r7.s()
            r2.e(r3, r7)
        L29:
            if (r1 >= r9) goto La
            boolean[] r2 = r15.f
            int r2 = com.google.android.gms.internal.ads.LA.c(r10, r1, r9, r2)
            if (r2 == r9) goto L6b
            int r3 = r2 + 3
            r3 = r10[r3]
            r3 = r3 & 126(0x7e, float:1.77E-43)
            if (r2 <= 0) goto L45
            int r4 = r2 + (-1)
            r5 = r10[r4]
            if (r5 != 0) goto L45
            r2 = 4
            r12 = r2
            r11 = r4
            goto L47
        L45:
            r11 = r2
            r12 = r8
        L47:
            int r2 = r11 - r1
            if (r2 <= 0) goto L4e
            r15.c(r1, r10, r11)
        L4e:
            int r1 = r9 - r11
            long r4 = r15.l
            long r13 = (long) r1
            long r4 = r4 - r13
            if (r2 >= 0) goto L58
            int r2 = -r2
            goto L59
        L58:
            r2 = 0
        L59:
            int r13 = r3 >> 1
            r3 = r4
            long r5 = r15.m
            r0 = r15
            r0.b(r1, r2, r3, r5)
            long r5 = r15.m
            r2 = r13
            r0.g(r1, r2, r3, r5)
            int r1 = r11 + r12
            goto L29
        L6b:
            r15.c(r1, r10, r9)
        L6e:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.W2.d(com.google.android.gms.internal.ads.Kn):void");
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void e(W w, C0591b1 c0591b1) {
        c0591b1.b();
        c0591b1.c();
        this.b = (String) c0591b1.e;
        c0591b1.c();
        InterfaceC2380n0 interfaceC2380n0Q = w.q(c0591b1.c, 2);
        this.c = interfaceC2380n0Q;
        this.d = new V2(interfaceC2380n0Q);
        this.a.u(w, c0591b1);
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void f(int i, long j) {
        this.m = j;
    }

    public final void g(int i, int i2, long j, long j2) {
        V2 v2 = this.d;
        boolean z = this.e;
        v2.g = false;
        v2.h = false;
        v2.e = j2;
        v2.d = 0;
        v2.b = j;
        if (i2 >= 32 && i2 != 40) {
            if (v2.i && !v2.j) {
                if (z) {
                    v2.a(i);
                }
                v2.i = false;
            }
            if (i2 <= 35 || i2 == 39) {
                v2.h = !v2.j;
                v2.j = true;
            }
        }
        boolean z2 = i2 >= 16 && i2 <= 21;
        v2.c = z2;
        v2.f = z2 || i2 <= 9;
        if (!this.e) {
            this.g.h(i2);
            this.h.h(i2);
            this.i.h(i2);
        }
        this.j.h(i2);
        this.k.h(i2);
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void zze() {
        this.l = 0L;
        this.m = -9223372036854775807L;
        LA.J(this.f);
        this.g.g();
        this.h.g();
        this.i.g();
        this.j.g();
        this.k.g();
        ((androidx.navigation.internal.m) this.a.d).q(0);
        V2 v2 = this.d;
        if (v2 != null) {
            v2.f = false;
            v2.g = false;
            v2.h = false;
            v2.i = false;
            v2.j = false;
        }
    }
}
