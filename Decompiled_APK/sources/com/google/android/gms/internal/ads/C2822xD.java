package com.google.android.gms.internal.ads;

import android.util.Pair;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.xD, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2822xD {
    public final WD c;
    public final Bo d;
    public long e;
    public int f;
    public boolean g;
    public C2693uD h;
    public C2693uD i;
    public C2693uD j;
    public C2693uD k;
    public C2693uD l;
    public int m;
    public Object n;
    public long o;
    public final Sq q;
    public final C2303l9 a = new C2303l9();
    public final C2518q9 b = new C2518q9();
    public ArrayList p = new ArrayList();

    public C2822xD(WD wd, Bo bo, Sq sq, C1829aD c1829aD) {
        this.c = wd;
        this.d = bo;
        this.q = sq;
    }

    public static C2093gF g(A9 a9, Object obj, long j, C2518q9 c2518q9, C2303l9 c2303l9) {
        a9.n(obj, c2303l9);
        a9.e(c2303l9.c, c2518q9, 0L);
        a9.a(obj);
        c2303l9.f.getClass();
        a9.n(obj, c2303l9);
        c2303l9.f.a(-1);
        return new C2093gF(obj, j, -1);
    }

    public final void A() {
        C2693uD c2693uD = this.l;
        if (c2693uD == null || c2693uD.k()) {
            this.l = null;
            for (int i = 0; i < this.p.size(); i++) {
                C2693uD c2693uD2 = (C2693uD) this.p.get(i);
                if (!c2693uD2.k()) {
                    this.l = c2693uD2;
                    return;
                }
            }
        }
    }

    /* JADX WARN: Type inference failed for: r1v4, types: [com.google.android.gms.internal.ads.BF, java.lang.Object] */
    public final void B(long j) {
        C2693uD c2693uD = this.k;
        if (c2693uD != null) {
            AbstractC1795We.L(c2693uD.m == null);
            if (c2693uD.e) {
                c2693uD.a.d(j - c2693uD.p);
            }
        }
    }

    public final void C() {
        if (this.p.isEmpty()) {
            return;
        }
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < this.p.size(); i++) {
            ((C2693uD) this.p.get(i)).i();
        }
        this.p = arrayList;
        this.l = null;
        A();
    }

    public final void D(C1829aD c1829aD) {
        c1829aD.getClass();
        C();
    }

    public final boolean E() {
        C2693uD c2693uD = this.k;
        if (c2693uD != null) {
            return !c2693uD.g.h && c2693uD.j() && this.k.g.e != -9223372036854775807L && this.m < 100;
        }
        return true;
    }

    public final int a(A9 a9) {
        A9 a92;
        C2693uD c2693uD;
        C2693uD c2693uD2 = this.h;
        if (c2693uD2 == null) {
            return 0;
        }
        int iA = a9.a(c2693uD2.b);
        while (true) {
            a92 = a9;
            iA = a92.i(iA, this.a, this.b, this.f, this.g);
            while (true) {
                c2693uD = c2693uD2.m;
                if (c2693uD == null || c2693uD2.g.f) {
                    break;
                }
                c2693uD2 = c2693uD;
            }
            if (iA == -1 || c2693uD == null || a92.a(c2693uD.b) != iA) {
                break;
            }
            c2693uD2 = c2693uD;
            a9 = a92;
        }
        int iK = k(c2693uD2);
        c2693uD2.g = x(a92, c2693uD2.g);
        return iK;
    }

    public final long b(Object obj) {
        for (int i = 0; i < this.p.size(); i++) {
            C2693uD c2693uD = (C2693uD) this.p.get(i);
            if (c2693uD.b.equals(obj)) {
                return c2693uD.g.a.d;
            }
        }
        return -1L;
    }

    public final C2736vD c(A9 a9, C2693uD c2693uD, long j) {
        int i;
        A9 a92;
        C2303l9 c2303l9;
        long j2;
        int i2;
        C2518q9 c2518q9;
        Object obj;
        C2303l9 c2303l92;
        long j3;
        A9 a93;
        long j4;
        long jB;
        C2736vD c2736vD = c2693uD.g;
        long j5 = c2693uD.p;
        long j6 = c2736vD.e;
        long j7 = (j5 + j6) - j;
        boolean z = c2736vD.f;
        long jLongValue = 0;
        long jLongValue2 = c2736vD.c;
        C2093gF c2093gF = c2736vD.a;
        if (z) {
            Object obj2 = c2093gF.a;
            int iA = a9.a(obj2);
            int i3 = this.f;
            boolean z2 = this.g;
            C2303l9 c2303l93 = this.a;
            C2518q9 c2518q92 = this.b;
            int i4 = a9.i(iA, c2303l93, c2518q92, i3, z2);
            if (i4 != -1) {
                int i5 = a9.d(i4, c2303l93, true).c;
                Object obj3 = c2303l93.b;
                obj3.getClass();
                if (a9.e(i5, c2518q92, 0L).k == i4) {
                    Pair pairM = a9.m(c2518q92, c2303l93, i5, -9223372036854775807L, Math.max(0L, j7));
                    if (pairM != null) {
                        Object obj4 = pairM.first;
                        jLongValue = ((Long) pairM.second).longValue();
                        C2693uD c2693uD2 = c2693uD.m;
                        if (c2693uD2 == null || !c2693uD2.b.equals(obj4)) {
                            jB = b(obj4);
                            if (jB == -1) {
                                jB = this.e;
                                this.e = 1 + jB;
                            }
                        } else {
                            jB = c2693uD2.g.a.d;
                        }
                        c2518q9 = c2518q92;
                        obj = obj4;
                        c2303l92 = c2303l93;
                        j3 = jB;
                        a93 = a9;
                        j4 = -9223372036854775807L;
                    }
                } else {
                    c2518q9 = c2518q92;
                    obj = obj3;
                    c2303l92 = c2303l93;
                    j3 = c2093gF.d;
                    a93 = a9;
                    j4 = 0;
                }
                C2093gF c2093gFG = g(a93, obj, j3, c2518q9, c2303l92);
                C2303l9 c2303l94 = c2303l92;
                if (j4 != -9223372036854775807L && jLongValue2 != -9223372036854775807L) {
                    a93.n(obj2, c2303l94).f.getClass();
                    c2303l94.f.getClass();
                }
                return d(a93, c2093gFG, j4, jLongValue);
            }
        } else {
            Object obj5 = c2093gF.a;
            C2303l9 c2303l95 = this.a;
            a9.n(obj5, c2303l95);
            if (!c2093gF.b()) {
                int i6 = c2093gF.e;
                if (i6 != -1) {
                    c2303l95.f.getClass();
                    if (i6 == -1) {
                        c2303l95.f.a(-1);
                    }
                }
                C1815a c1815aA = c2303l95.f.a(i6);
                int i7 = 0;
                while (true) {
                    int[] iArr = c1815aA.d;
                    if (i7 >= iArr.length || (i = iArr[i7]) == 0 || i == 1) {
                        break;
                    }
                    i7++;
                }
                c2303l95.c(i6);
                if (i7 != c2303l95.f.a(i6).a) {
                    return e(a9, obj5, i6, i7, j6, c2093gF.d);
                }
                a9.n(obj5, c2303l95);
                c2303l95.f.a(i6).getClass();
                c2303l95.f.a(i6).getClass();
                return f(a9, obj5, 0L, j6, c2093gF.d);
            }
            P5 p5 = c2303l95.f;
            int i8 = c2093gF.b;
            if (p5.a(i8).a != -1) {
                C1815a c1815aA2 = c2303l95.f.a(i8);
                int i9 = c2093gF.c + 1;
                while (true) {
                    int[] iArr2 = c1815aA2.d;
                    if (i9 >= iArr2.length || (i2 = iArr2[i9]) == 0 || i2 == 1) {
                        break;
                    }
                    i9++;
                }
                if (i9 < 0) {
                    return e(a9, obj5, i8, i9, c2736vD.c, c2093gF.d);
                }
                if (jLongValue2 == -9223372036854775807L) {
                    c2303l9 = c2303l95;
                    a92 = a9;
                    Pair pairM2 = a92.m(this.b, c2303l9, c2303l95.c, -9223372036854775807L, Math.max(0L, j7));
                    if (pairM2 == null) {
                        return null;
                    }
                    jLongValue2 = ((Long) pairM2.second).longValue();
                    j2 = -9223372036854775807L;
                } else {
                    a92 = a9;
                    c2303l9 = c2303l95;
                    j2 = jLongValue2;
                }
                a92.n(obj5, c2303l9);
                c2303l9.f.a(i8).getClass();
                c2303l9.f.a(i8).getClass();
                return f(a92, obj5, Math.max(0L, jLongValue2), j2, c2093gF.d);
            }
        }
        return null;
    }

    public final C2736vD d(A9 a9, C2093gF c2093gF, long j, long j2) {
        Object obj = c2093gF.a;
        a9.n(obj, this.a);
        return c2093gF.b() ? e(a9, obj, c2093gF.b, c2093gF.c, j, c2093gF.d) : f(a9, obj, j2, j, c2093gF.d);
    }

    public final C2736vD e(A9 a9, Object obj, int i, int i2, long j, long j2) {
        int i3;
        C2093gF c2093gF = new C2093gF(obj, i, i2, j2, -1);
        C2303l9 c2303l9 = this.a;
        long jA = a9.n(obj, c2303l9).a(i, i2);
        C1815a c1815aA = c2303l9.f.a(i);
        int i4 = 0;
        while (true) {
            int[] iArr = c1815aA.d;
            if (i4 >= iArr.length || (i3 = iArr[i4]) == 0 || i3 == 1) {
                break;
            }
            i4++;
        }
        if (i2 == i4) {
            c2303l9.f.getClass();
        }
        c2303l9.c(i);
        long jMax = 0;
        if (jA != -9223372036854775807L && jA <= 0) {
            jMax = Math.max(0L, (-1) + jA);
        }
        return new C2736vD(c2093gF, jMax, j, -9223372036854775807L, jA, false, false, false);
    }

    public final C2736vD f(A9 a9, Object obj, long j, long j2, long j3) {
        C2303l9 c2303l9 = this.a;
        a9.n(obj, c2303l9);
        c2303l9.getClass();
        c2303l9.f.getClass();
        C2093gF c2093gF = new C2093gF(obj, j3, -1);
        boolean z = !c2093gF.b();
        boolean zJ = j(a9, c2093gF);
        boolean zI = i(a9, c2093gF, z);
        long j4 = c2303l9.d;
        return new C2736vD(c2093gF, (j4 == -9223372036854775807L || j < j4) ? j : Math.max(0L, (-1) + j4), j2, -9223372036854775807L, j4, z, zJ, zI);
    }

    public final void h() {
        C2244ju c2244ju = AbstractC2330lu.b;
        C2159hu c2159hu = new C2159hu(4);
        for (C2693uD c2693uD = this.h; c2693uD != null; c2693uD = c2693uD.m) {
            c2159hu.c(c2693uD.g.a);
        }
        C2693uD c2693uD2 = this.i;
        this.d.b(new C(this, c2159hu, c2693uD2 == null ? null : c2693uD2.g.a, 10));
    }

    public final boolean i(A9 a9, C2093gF c2093gF, boolean z) {
        int iA = a9.a(c2093gF.a);
        C2303l9 c2303l9 = this.a;
        int i = a9.d(iA, c2303l9, false).c;
        C2518q9 c2518q9 = this.b;
        return !a9.e(i, c2518q9, 0L).g && a9.i(iA, c2303l9, c2518q9, this.f, this.g) == -1 && z;
    }

    public final boolean j(A9 a9, C2093gF c2093gF) {
        if (!c2093gF.b() && c2093gF.e == -1) {
            Object obj = c2093gF.a;
            if (a9.e(a9.n(obj, this.a).c, this.b, 0L).l == a9.a(obj)) {
                return true;
            }
        }
        return false;
    }

    public final int k(C2693uD c2693uD) {
        AbstractC1795We.p(c2693uD);
        int i = 0;
        if (c2693uD.equals(this.k)) {
            return 0;
        }
        this.k = c2693uD;
        int i2 = 0;
        while (true) {
            c2693uD = c2693uD.m;
            if (c2693uD == null) {
                break;
            }
            if (c2693uD == this.i) {
                C2693uD c2693uD2 = this.h;
                this.i = c2693uD2;
                this.j = c2693uD2;
                i2 = 3;
            }
            if (c2693uD == this.j) {
                this.j = this.i;
                i2 |= 2;
            }
            c2693uD.i();
            this.m--;
        }
        C2693uD c2693uD3 = this.k;
        c2693uD3.getClass();
        if (c2693uD3.m != null) {
            c2693uD3.l();
            c2693uD3.m = null;
            while (true) {
                YF yf = c2693uD3.o;
                if (i >= yf.a) {
                    break;
                }
                yf.b(i);
                XF xf = ((XF[]) c2693uD3.o.c)[i];
                i++;
            }
        }
        h();
        return i2;
    }

    /* JADX WARN: Code restructure failed: missing block: B:60:0x00a9, code lost:
    
        return k(r3);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int l(com.google.android.gms.internal.ads.A9 r17, long r18, long r20, long r22) {
        /*
            r16 = this;
            r0 = r16
            r1 = r17
            com.google.android.gms.internal.ads.uD r2 = r0.h
            r3 = 0
        L7:
            r4 = 0
            if (r2 == 0) goto Laa
            com.google.android.gms.internal.ads.vD r5 = r2.g
            if (r3 != 0) goto L15
            com.google.android.gms.internal.ads.vD r3 = r0.x(r1, r5)
            r6 = r18
            goto L30
        L15:
            r6 = r18
            com.google.android.gms.internal.ads.vD r8 = r0.c(r1, r3, r6)
            if (r8 == 0) goto La5
            long r9 = r5.b
            long r11 = r8.b
            int r9 = (r9 > r11 ? 1 : (r9 == r11 ? 0 : -1))
            if (r9 != 0) goto La5
            com.google.android.gms.internal.ads.gF r9 = r5.a
            com.google.android.gms.internal.ads.gF r10 = r8.a
            boolean r9 = r9.equals(r10)
            if (r9 == 0) goto La5
            r3 = r8
        L30:
            long r8 = r5.c
            com.google.android.gms.internal.ads.vD r8 = r3.a(r8)
            r2.g = r8
            long r9 = r5.e
            long r11 = r3.e
            int r3 = (r9 > r11 ? 1 : (r9 == r11 ? 0 : -1))
            if (r3 == 0) goto L9e
            java.lang.Object r1 = r2.a
            boolean r3 = r1 instanceof com.google.android.gms.internal.ads.PE
            r5 = -9223372036854775808
            r13 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            if (r3 == 0) goto L58
            long r7 = r8.d
            int r3 = (r7 > r13 ? 1 : (r7 == r13 ? 0 : -1))
            if (r3 != 0) goto L54
            r7 = r5
        L54:
            com.google.android.gms.internal.ads.PE r1 = (com.google.android.gms.internal.ads.PE) r1
            r1.e = r7
        L58:
            int r1 = (r11 > r13 ? 1 : (r11 == r13 ? 0 : -1))
            if (r1 != 0) goto L62
            r7 = 9223372036854775807(0x7fffffffffffffff, double:NaN)
            goto L65
        L62:
            long r7 = r2.p
            long r7 = r7 + r11
        L65:
            com.google.android.gms.internal.ads.uD r1 = r0.i
            r3 = 1
            if (r2 != r1) goto L74
            int r1 = (r20 > r5 ? 1 : (r20 == r5 ? 0 : -1))
            if (r1 == 0) goto L72
            int r1 = (r20 > r7 ? 1 : (r20 == r7 ? 0 : -1))
            if (r1 < 0) goto L74
        L72:
            r1 = r3
            goto L75
        L74:
            r1 = r4
        L75:
            com.google.android.gms.internal.ads.uD r11 = r0.j
            if (r2 != r11) goto L83
            int r5 = (r22 > r5 ? 1 : (r22 == r5 ? 0 : -1))
            if (r5 == 0) goto L81
            int r5 = (r22 > r7 ? 1 : (r22 == r7 ? 0 : -1))
            if (r5 < 0) goto L83
        L81:
            r5 = r3
            goto L84
        L83:
            r5 = r4
        L84:
            int r2 = r0.k(r2)
            if (r2 == 0) goto L8b
            return r2
        L8b:
            int r2 = (r9 > r13 ? 1 : (r9 == r13 ? 0 : -1))
            if (r2 != 0) goto L90
            r9 = r13
        L90:
            if (r1 == 0) goto L98
            int r1 = (r9 > r13 ? 1 : (r9 == r13 ? 0 : -1))
            if (r1 != 0) goto L97
            goto L98
        L97:
            r4 = r3
        L98:
            if (r5 == 0) goto L9d
            r1 = r4 | 2
            return r1
        L9d:
            return r4
        L9e:
            com.google.android.gms.internal.ads.uD r3 = r2.m
            r15 = r3
            r3 = r2
            r2 = r15
            goto L7
        La5:
            int r1 = r0.k(r3)
            return r1
        Laa:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2822xD.l(com.google.android.gms.internal.ads.A9, long, long, long):int");
    }

    public final int m(A9 a9, int i) {
        this.f = i;
        return a(a9);
    }

    public final int n(A9 a9, boolean z) {
        this.g = z;
        return a(a9);
    }

    public final C2693uD o() {
        C2693uD c2693uD = this.h;
        if (c2693uD == null) {
            return null;
        }
        if (c2693uD == this.i) {
            this.i = c2693uD.m;
        }
        if (c2693uD == this.j) {
            this.j = c2693uD.m;
        }
        c2693uD.i();
        int i = this.m - 1;
        this.m = i;
        if (i == 0) {
            this.k = null;
            C2693uD c2693uD2 = this.h;
            this.n = c2693uD2.b;
            this.o = c2693uD2.g.a.d;
        }
        this.h = this.h.m;
        h();
        return this.h;
    }

    public final void p() {
        C2693uD c2693uD = this.j;
        AbstractC1795We.p(c2693uD);
        this.j = c2693uD.m;
        h();
        AbstractC1795We.p(this.j);
    }

    public final C2693uD q() {
        C2693uD c2693uD = this.j;
        C2693uD c2693uD2 = this.i;
        if (c2693uD == c2693uD2) {
            AbstractC1795We.p(c2693uD2);
            this.j = c2693uD2.m;
        }
        C2693uD c2693uD3 = this.i;
        AbstractC1795We.p(c2693uD3);
        this.i = c2693uD3.m;
        h();
        C2693uD c2693uD4 = this.i;
        AbstractC1795We.p(c2693uD4);
        return c2693uD4;
    }

    public final C2693uD r(C2736vD c2736vD) {
        C2693uD c2693uD;
        C2693uD c2693uD2 = this.k;
        long j = c2736vD.b;
        long j2 = c2693uD2 == null ? 1000000000000L : (c2693uD2.p + c2693uD2.g.e) - j;
        int i = 0;
        while (true) {
            if (i >= this.p.size()) {
                c2693uD = null;
                break;
            }
            C2736vD c2736vD2 = ((C2693uD) this.p.get(i)).g;
            long j3 = c2736vD2.e;
            if ((j3 == -9223372036854775807L || j3 == c2736vD.e) && c2736vD2.b == j && c2736vD2.a.equals(c2736vD.a)) {
                c2693uD = (C2693uD) this.p.remove(i);
                break;
            }
            i++;
        }
        if (c2693uD == null) {
            C2436oD c2436oD = (C2436oD) this.q.a;
            C1963dG c1963dGN = c2436oD.f.n();
            c2436oD.f1.getClass();
            c2693uD = new C2693uD(c2436oD.b, j2, c2436oD.d, c1963dGN, c2436oD.r, c2736vD, c2436oD.e);
        } else {
            c2693uD.g = c2736vD;
            c2693uD.p = j2;
        }
        C2693uD c2693uD3 = this.k;
        if (c2693uD3 == null) {
            this.h = c2693uD;
            this.i = c2693uD;
            this.j = c2693uD;
        } else if (c2693uD != c2693uD3.m) {
            c2693uD3.l();
            c2693uD3.m = c2693uD;
        }
        this.n = null;
        this.k = c2693uD;
        this.m++;
        h();
        return c2693uD;
    }

    public final C2693uD s() {
        return this.h;
    }

    public final C2693uD t(InterfaceC2005eF interfaceC2005eF) {
        for (int i = 0; i < this.p.size(); i++) {
            C2693uD c2693uD = (C2693uD) this.p.get(i);
            if (c2693uD.a == interfaceC2005eF) {
                return c2693uD;
            }
        }
        return null;
    }

    public final C2693uD u() {
        return this.j;
    }

    public final C2693uD v() {
        return this.i;
    }

    public final C2736vD w(long j, GD gd) {
        C2693uD c2693uD = this.k;
        return c2693uD == null ? d(gd.a, gd.b, gd.c, gd.r) : c(gd.a, c2693uD, j);
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0065  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0069  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.ads.C2736vD x(com.google.android.gms.internal.ads.A9 r19, com.google.android.gms.internal.ads.C2736vD r20) {
        /*
            r18 = this;
            r0 = r18
            r1 = r19
            r2 = r20
            com.google.android.gms.internal.ads.gF r3 = r2.a
            boolean r4 = r3.b()
            r5 = -1
            int r6 = r3.e
            if (r4 != 0) goto L16
            if (r6 != r5) goto L16
            r4 = 1
        L14:
            r11 = r4
            goto L18
        L16:
            r4 = 0
            goto L14
        L18:
            boolean r12 = r0.j(r1, r3)
            boolean r13 = r0.i(r1, r3, r11)
            java.lang.Object r4 = r3.a
            com.google.android.gms.internal.ads.l9 r7 = r0.a
            r1.n(r4, r7)
            boolean r1 = r3.b()
            r8 = 0
            r14 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            if (r1 != 0) goto L36
            if (r6 != r5) goto L39
        L36:
            r16 = r14
            goto L44
        L39:
            com.google.android.gms.internal.ads.P5 r1 = r7.f
            com.google.android.gms.internal.ads.a r1 = r1.a(r6)
            r1.getClass()
            r16 = r8
        L44:
            boolean r1 = r3.b()
            int r4 = r3.b
            if (r1 == 0) goto L56
            int r1 = r3.c
            long r8 = r7.a(r4, r1)
        L52:
            r14 = r8
            r8 = r16
            goto L5f
        L56:
            int r1 = (r16 > r14 ? 1 : (r16 == r14 ? 0 : -1))
            if (r1 == 0) goto L5c
            r14 = r8
            goto L5f
        L5c:
            long r8 = r7.d
            goto L52
        L5f:
            boolean r1 = r3.b()
            if (r1 == 0) goto L69
            r7.c(r4)
            goto L6e
        L69:
            if (r6 == r5) goto L6e
            r7.c(r6)
        L6e:
            com.google.android.gms.internal.ads.vD r1 = new com.google.android.gms.internal.ads.vD
            r5 = r3
            long r3 = r2.b
            long r6 = r2.c
            r2 = r5
            r5 = r6
            r7 = r8
            r9 = r14
            r1.<init>(r2, r3, r5, r7, r9, r11, r12, r13)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2822xD.x(com.google.android.gms.internal.ads.A9, com.google.android.gms.internal.ads.vD):com.google.android.gms.internal.ads.vD");
    }

    public final C2093gF y(A9 a9, Object obj) {
        long jB;
        int iA;
        C2303l9 c2303l9 = this.a;
        int i = a9.n(obj, c2303l9).c;
        Object obj2 = this.n;
        if (obj2 == null || (iA = a9.a(obj2)) == -1 || a9.d(iA, c2303l9, false).c != i) {
            C2693uD c2693uD = this.h;
            while (true) {
                if (c2693uD == null) {
                    C2693uD c2693uD2 = this.h;
                    while (true) {
                        if (c2693uD2 != null) {
                            int iA2 = a9.a(c2693uD2.b);
                            if (iA2 != -1 && a9.d(iA2, c2303l9, false).c == i) {
                                jB = c2693uD2.g.a.d;
                                break;
                            }
                            c2693uD2 = c2693uD2.m;
                        } else {
                            jB = b(obj);
                            if (jB == -1) {
                                jB = this.e;
                                this.e = 1 + jB;
                                if (this.h == null) {
                                    this.n = obj;
                                    this.o = jB;
                                }
                            }
                        }
                    }
                } else {
                    if (c2693uD.b.equals(obj)) {
                        jB = c2693uD.g.a.d;
                        break;
                    }
                    c2693uD = c2693uD.m;
                }
            }
        } else {
            jB = this.o;
        }
        long j = jB;
        a9.n(obj, c2303l9);
        int i2 = c2303l9.c;
        C2518q9 c2518q9 = this.b;
        a9.e(i2, c2518q9, 0L);
        for (int iA3 = a9.a(obj); iA3 >= c2518q9.k; iA3--) {
            a9.d(iA3, c2303l9, true);
            c2303l9.f.getClass();
            c2303l9.f.a(-1);
        }
        return g(a9, obj, j, c2518q9, c2303l9);
    }

    public final void z() {
        if (this.m == 0) {
            return;
        }
        C2693uD c2693uD = this.h;
        AbstractC1795We.p(c2693uD);
        this.n = c2693uD.b;
        this.o = c2693uD.g.a.d;
        while (c2693uD != null) {
            c2693uD.i();
            c2693uD = c2693uD.m;
        }
        this.h = null;
        this.k = null;
        this.i = null;
        this.j = null;
        this.m = 0;
        h();
    }
}
