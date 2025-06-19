package com.google.android.gms.internal.ads;

import java.io.EOFException;
import java.io.InterruptedIOException;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.p1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2467p1 implements U {
    public C2695uF e;
    public InterfaceC2380n0 f;
    public int h;
    public K4 i;
    public long k;
    public long l;
    public int n;
    public InterfaceC2552r1 o;
    public boolean p;
    public final Kn a = new Kn(10);
    public final C2034f0 b = new C2034f0();
    public final C1860b0 c = new C1860b0();
    public long j = -9223372036854775807L;
    public final C1947d0 d = new C1947d0(0);
    public InterfaceC2380n0 g = new T();
    public long m = -1;

    public final void a() {
        InterfaceC2552r1 interfaceC2552r1 = this.o;
        if ((interfaceC2552r1 instanceof C2381n1) && ((C2381n1) interfaceC2552r1).g()) {
            long j = this.m;
            if (j == -1 || j == this.o.j()) {
                return;
            }
            C2381n1 c2381n1 = (C2381n1) this.o;
            this.o = new C2381n1(c2381n1.h, c2381n1.i, this.m, c2381n1.g);
            C2695uF c2695uF = this.e;
            c2695uF.getClass();
            c2695uF.p(this.o);
            this.f.getClass();
            this.o.zza();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x001a A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean b(com.google.android.gms.internal.ads.P r9) {
        /*
            r8 = this;
            com.google.android.gms.internal.ads.r1 r0 = r8.o
            r1 = 1
            if (r0 == 0) goto L1a
            long r2 = r0.j()
            r4 = -1
            int r0 = (r2 > r4 ? 1 : (r2 == r4 ? 0 : -1))
            if (r0 == 0) goto L1a
            long r4 = r9.zze()
            r6 = -4
            long r2 = r2 + r6
            int r0 = (r4 > r2 ? 1 : (r4 == r2 ? 0 : -1))
            if (r0 > 0) goto L28
        L1a:
            com.google.android.gms.internal.ads.Kn r0 = r8.a     // Catch: java.io.EOFException -> L28
            byte[] r0 = r0.a     // Catch: java.io.EOFException -> L28
            r2 = 4
            r3 = 0
            boolean r9 = r9.k(r0, r3, r2, r1)     // Catch: java.io.EOFException -> L28
            if (r9 != 0) goto L27
            goto L28
        L27:
            return r3
        L28:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2467p1.b(com.google.android.gms.internal.ads.P):boolean");
    }

    public final boolean c(P p, boolean z) throws EOFException, InterruptedIOException {
        int iZze;
        int i;
        int iK;
        p.f = 0;
        if (p.d == 0) {
            K4 k4B = this.d.b(p, null);
            this.i = k4B;
            if (k4B != null) {
                this.c.a(k4B);
            }
            iZze = (int) p.zze();
            if (!z) {
                p.p(iZze);
            }
            i = 0;
        } else {
            iZze = 0;
            i = 0;
        }
        int i2 = i;
        int i3 = i2;
        while (true) {
            if (!b(p)) {
                Kn kn = this.a;
                kn.j(0);
                int iU = kn.u();
                if ((i == 0 || ((-128000) & iU) == (i & (-128000))) && (iK = AbstractC2096gb.k(iU)) != -1) {
                    i2++;
                    if (i2 != 1) {
                        if (i2 == 4) {
                            break;
                        }
                    } else {
                        this.b.a(iU);
                        i = iU;
                    }
                    p.n(iK - 4, false);
                } else {
                    int i4 = i3 + 1;
                    if (i3 == (true != z ? 131072 : 32768)) {
                        if (z) {
                            return false;
                        }
                        a();
                        throw new EOFException();
                    }
                    if (z) {
                        p.f = 0;
                        p.n(iZze + i4, false);
                    } else {
                        p.p(1);
                    }
                    i = 0;
                    i3 = i4;
                    i2 = 0;
                }
            } else if (i2 <= 0) {
                a();
                throw new EOFException();
            }
        }
        if (z) {
            p.p(iZze + i3);
        } else {
            p.f = 0;
        }
        this.h = i;
        return true;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final boolean d(V v) {
        return c((P) v, true);
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        C2695uF c2695uF = (C2695uF) w;
        this.e = c2695uF;
        InterfaceC2380n0 interfaceC2380n0Q = c2695uF.q(0, 1);
        this.f = interfaceC2380n0Q;
        this.g = interfaceC2380n0Q;
        this.e.n();
    }

    /* JADX WARN: Removed duplicated region for block: B:141:0x02dc  */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0044  */
    /* JADX WARN: Removed duplicated region for block: B:160:0x0364  */
    /* JADX WARN: Removed duplicated region for block: B:163:0x0369  */
    /* JADX WARN: Removed duplicated region for block: B:164:0x0373  */
    /* JADX WARN: Removed duplicated region for block: B:175:0x03ec  */
    /* JADX WARN: Removed duplicated region for block: B:177:0x0403  */
    /* JADX WARN: Removed duplicated region for block: B:184:0x0422  */
    /* JADX WARN: Removed duplicated region for block: B:202:0x048e  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0062  */
    /* JADX WARN: Removed duplicated region for block: B:220:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:25:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0080  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0091  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x019b  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0023  */
    @Override // com.google.android.gms.internal.ads.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f(com.google.android.gms.internal.ads.V r50, androidx.compose.foundation.lazy.layout.C0429a r51) throws java.io.EOFException, java.io.InterruptedIOException {
        /*
            Method dump skipped, instructions count: 1210
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2467p1.f(com.google.android.gms.internal.ads.V, androidx.compose.foundation.lazy.layout.a):int");
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void h(long j, long j2) {
        this.h = 0;
        this.j = -9223372036854775807L;
        this.k = 0L;
        this.n = 0;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final List j() {
        C2244ju c2244ju = AbstractC2330lu.b;
        return Bu.e;
    }
}
