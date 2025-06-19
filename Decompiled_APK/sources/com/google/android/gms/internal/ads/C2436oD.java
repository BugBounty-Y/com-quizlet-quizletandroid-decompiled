package com.google.android.gms.internal.ads;

import android.content.Context;
import android.media.MediaFormat;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.SystemClock;
import android.util.Pair;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.oD, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2436oD implements Handler.Callback, InterfaceC1962dF, HD, InterfaceC2636t {
    public static final long l1 = Yo.w(10000);
    public boolean A;
    public C2393nD B;
    public GD C;
    public androidx.recyclerview.widget.N D;
    public boolean E;
    public boolean G;
    public boolean H;
    public boolean J;
    public boolean M;
    public int V;
    public C2393nD W;
    public long X;
    public long Y;
    public int Z;
    public final androidx.transition.V[] a;
    public final JE[] b;
    public final boolean[] c;
    public boolean c1;
    public final VF d;
    public zzik d1;
    public final YF e;
    public final InterfaceC2522qD f;
    public C1829aD f1;
    public final C2050fG g;
    public final Bo h;
    public boolean h1;
    public final As i;
    public final Looper j;
    public final C2586rt j1;
    public final C2518q9 k;
    public final SC k1;
    public final C2303l9 l;
    public final long m;
    public final Oo n;
    public final ArrayList o;
    public final C1847ao p;
    public final C2822xD q;
    public final C2538qn r;
    public final long s;
    public final C1917cE t;
    public final WD u;
    public final Bo v;
    public final boolean w;
    public final PC x;
    public OD y;
    public boolean z;
    public long g1 = -9223372036854775807L;
    public int K = 0;
    public boolean L = false;
    public boolean F = false;
    public float i1 = 1.0f;
    public long e1 = -9223372036854775807L;
    public long I = -9223372036854775807L;

    public C2436oD(Context context, JE[] jeArr, JE[] jeArr2, VF vf, YF yf, InterfaceC2522qD interfaceC2522qD, C2050fG c2050fG, WD wd, OD od, SC sc, long j, Looper looper, C1847ao c1847ao, C2586rt c2586rt, C1917cE c1917cE, C1829aD c1829aD) {
        Looper looper2;
        this.j1 = c2586rt;
        this.d = vf;
        this.e = yf;
        this.f = interfaceC2522qD;
        this.g = c2050fG;
        boolean z = false;
        this.y = od;
        this.k1 = sc;
        this.s = j;
        this.p = c1847ao;
        this.t = c1917cE;
        this.f1 = c1829aD;
        this.u = wd;
        this.m = interfaceC2522qD.zzb();
        X8 x8 = A9.a;
        GD gdH = GD.h(yf);
        this.C = gdH;
        this.D = new androidx.recyclerview.widget.N(gdH);
        int length = jeArr.length;
        this.b = new JE[2];
        this.c = new boolean[2];
        vf.getClass();
        this.a = new androidx.transition.V[2];
        int i = 0;
        boolean z2 = false;
        for (int i2 = 2; i < i2; i2 = 2) {
            JE je = jeArr[i];
            je.e = i;
            je.f = c1917cE;
            je.g = c1847ao;
            JE[] jeArr3 = this.b;
            je.getClass();
            jeArr3[i] = je;
            JE je2 = this.b[i];
            synchronized (je2.a) {
                je2.r = vf;
            }
            JE je3 = jeArr2[i];
            if (je3 != null) {
                je3.e = i;
                je3.f = c1917cE;
                je3.g = c1847ao;
                z2 = true;
            }
            androidx.transition.V[] vArr = this.a;
            JE je4 = jeArr[i];
            androidx.transition.V v = new androidx.transition.V();
            v.e = je4;
            v.a = i;
            v.f = je3;
            v.b = 0;
            v.c = false;
            v.d = false;
            vArr[i] = v;
            i++;
        }
        this.w = z2;
        this.n = new Oo(this);
        this.o = new ArrayList();
        this.k = new C2518q9();
        this.l = new C2303l9();
        vf.a = this;
        vf.b = c2050fG;
        this.c1 = true;
        Bo boA = c1847ao.a(looper, null);
        this.v = boA;
        this.q = new C2822xD(wd, boA, new Sq(this), c1829aD);
        this.r = new C2538qn(this, wd, boA, c1917cE);
        As as = new As();
        this.i = as;
        synchronized (as.b) {
            try {
                if (((Looper) as.c) == null) {
                    if (as.a == 0 && ((HandlerThread) as.d) == null) {
                        z = true;
                    }
                    AbstractC1795We.L(z);
                    HandlerThread handlerThread = new HandlerThread("ExoPlayer:Playback", -16);
                    as.d = handlerThread;
                    handlerThread.start();
                    as.c = ((HandlerThread) as.d).getLooper();
                }
                as.a++;
                looper2 = (Looper) as.c;
            } catch (Throwable th) {
                throw th;
            }
        }
        this.j = looper2;
        Bo boA2 = c1847ao.a(looper2, this);
        this.h = boA2;
        this.x = new PC(context, looper2, this);
        boA2.a(35, new InterfaceC2636t() { // from class: com.google.android.gms.internal.ads.kD
            @Override // com.google.android.gms.internal.ads.InterfaceC2636t
            public final void a(long j2, long j3, C1832aG c1832aG, MediaFormat mediaFormat) {
                this.a.a(j2, j3, c1832aG, mediaFormat);
            }
        }).a();
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [com.google.android.gms.internal.ads.BF, com.google.android.gms.internal.ads.eF, java.lang.Object] */
    public static final boolean R(C2693uD c2693uD) {
        if (c2693uD != null) {
            try {
                ?? r1 = c2693uD.a;
                if (c2693uD.e) {
                    AF[] afArr = c2693uD.c;
                    for (int i = 0; i < 2; i++) {
                        AF af = afArr[i];
                        if (af != null) {
                            af.j();
                        }
                    }
                } else {
                    r1.i();
                }
                if ((!c2693uD.e ? 0L : r1.a()) != Long.MIN_VALUE) {
                    return true;
                }
            } catch (IOException unused) {
            }
        }
        return false;
    }

    public static int S(C2518q9 c2518q9, C2303l9 c2303l9, int i, boolean z, Object obj, A9 a9, A9 a92) {
        C2518q9 c2518q92 = c2518q9;
        A9 a93 = a9;
        Object obj2 = a93.e(a93.n(obj, c2303l9).c, c2518q9, 0L).a;
        for (int i2 = 0; i2 < a92.c(); i2++) {
            if (a92.e(i2, c2518q9, 0L).a.equals(obj2)) {
                return i2;
            }
        }
        int iA = a93.a(obj);
        int iB = a93.b();
        int iA2 = -1;
        int i3 = 0;
        while (true) {
            if (i3 >= iB || iA2 != -1) {
                break;
            }
            A9 a94 = a93;
            int i4 = a94.i(iA, c2303l9, c2518q92, i, z);
            if (i4 == -1) {
                iA2 = -1;
                break;
            }
            iA2 = a92.a(a94.f(i4));
            i3++;
            a93 = a94;
            iA = i4;
            c2518q92 = c2518q9;
        }
        if (iA2 == -1) {
            return -1;
        }
        return a92.d(iA2, c2303l9, false).c;
    }

    public static Pair d(A9 a9, C2393nD c2393nD, int i, boolean z, C2518q9 c2518q9, C2303l9 c2303l9) {
        A9 a92 = c2393nD.a;
        if (a9.o()) {
            return null;
        }
        A9 a93 = true == a92.o() ? a9 : a92;
        try {
            Pair pairL = a93.l(c2518q9, c2303l9, c2393nD.b, c2393nD.c);
            if (!a9.equals(a93)) {
                if (a9.a(pairL.first) == -1) {
                    int iS = S(c2518q9, c2303l9, i, z, pairL.first, a93, a9);
                    if (iS != -1) {
                        return a9.l(c2518q9, c2303l9, iS, -9223372036854775807L);
                    }
                    return null;
                }
                if (a93.n(pairL.first, c2303l9).e && a93.e(c2303l9.c, c2518q9, 0L).k == a93.a(pairL.first)) {
                    return a9.l(c2518q9, c2303l9, a9.n(pairL.first, c2303l9).c, c2393nD.c);
                }
            }
            return pairL;
        } catch (IndexOutOfBoundsException unused) {
            return null;
        }
    }

    public final void A(boolean z) {
        C2093gF c2093gF = this.q.h.g.a;
        long jB = b(c2093gF, this.C.r, true, false);
        if (jB != this.C.r) {
            GD gd = this.C;
            this.C = e(c2093gF, jB, gd.c, gd.d, z, 5);
        }
    }

    /* JADX WARN: Type inference failed for: r0v26, types: [com.google.android.gms.internal.ads.eF, java.lang.Object] */
    public final void B(C2393nD c2393nD, boolean z) throws Throwable {
        long jLongValue;
        C2093gF c2093gFY;
        boolean z2;
        int i;
        long j;
        boolean z3;
        long j2;
        long jF;
        long j3;
        boolean z4;
        long j4;
        long j5;
        GD gd;
        int i2;
        this.D.e(z ? 1 : 0);
        if (this.A) {
            this.B = c2393nD;
            return;
        }
        A9 a9 = this.C.a;
        int i3 = this.K;
        boolean z5 = this.L;
        C2518q9 c2518q9 = this.k;
        C2303l9 c2303l9 = this.l;
        Pair pairD = d(a9, c2393nD, i3, z5, c2518q9, c2303l9);
        if (pairD == null) {
            Pair pairC = c(this.C.a);
            C2093gF c2093gF = (C2093gF) pairC.first;
            jLongValue = ((Long) pairC.second).longValue();
            z2 = !this.C.a.o();
            c2093gFY = c2093gF;
        } else {
            Object obj = pairD.first;
            jLongValue = ((Long) pairD.second).longValue();
            long j6 = c2393nD.c;
            j = j6 != -9223372036854775807L ? jLongValue : -9223372036854775807L;
            c2093gFY = this.q.y(this.C.a, obj);
            if (c2093gFY.b()) {
                this.C.a.n(c2093gFY.a, c2303l9);
                C1815a c1815aA = c2303l9.f.a(-1);
                int i4 = 0;
                while (true) {
                    int[] iArr = c1815aA.d;
                    if (i4 >= iArr.length || (i = iArr[i4]) == 0 || i == 1) {
                        break;
                    } else {
                        i4++;
                    }
                }
                if (i4 == -1) {
                    c2303l9.f.getClass();
                }
                jLongValue = 0;
                z2 = true;
            } else {
                z2 = j6 == -9223372036854775807L;
            }
        }
        try {
            if (this.C.a.o()) {
                this.W = c2393nD;
            } else if (pairD == null) {
                if (this.C.e != 1) {
                    C(4);
                }
                v(false, true, false, true);
            } else {
                if (c2093gFY.equals(this.C.b)) {
                    C2693uD c2693uD = this.q.h;
                    jF = (c2693uD == null || !c2693uD.e || jLongValue == 0) ? jLongValue : c2693uD.a.f(jLongValue, this.y);
                    if (Yo.w(jF) == Yo.w(this.C.r) && ((i2 = (gd = this.C).e) == 2 || i2 == 3)) {
                        jLongValue = gd.r;
                    }
                } else {
                    jF = jLongValue;
                }
                this.A = this.z;
                boolean z6 = this.C.e == 4;
                C2822xD c2822xD = this.q;
                if (c2822xD.h != c2822xD.i) {
                    j3 = jF;
                    z4 = true;
                } else {
                    j3 = jF;
                    z4 = false;
                }
                long jB = b(c2093gFY, j3, z4, z6);
                z3 = z2 | (jLongValue != jB);
                try {
                    GD gd2 = this.C;
                    C2093gF c2093gF2 = c2093gFY;
                    try {
                        A9 a92 = gd2.a;
                        long j7 = j;
                        try {
                            L(a92, c2093gF2, a92, gd2.b, j7, true);
                            c2093gFY = c2093gF2;
                            j4 = j7;
                            j5 = jB;
                            this.C = e(c2093gFY, j5, j4, j5, z3, 2);
                        } catch (Throwable th) {
                            th = th;
                            c2093gFY = c2093gF2;
                            j = j7;
                            j2 = jB;
                            this.C = e(c2093gFY, j2, j, j2, z3, 2);
                            throw th;
                        }
                    } catch (Throwable th2) {
                        th = th2;
                        c2093gFY = c2093gF2;
                        j = j;
                        j2 = jB;
                        this.C = e(c2093gFY, j2, j, j2, z3, 2);
                        throw th;
                    }
                } catch (Throwable th3) {
                    th = th3;
                }
            }
            z3 = z2;
            j4 = j;
            j5 = jLongValue;
            this.C = e(c2093gFY, j5, j4, j5, z3, 2);
        } catch (Throwable th4) {
            th = th4;
            j = j;
            z3 = z2;
            j2 = jLongValue;
        }
    }

    public final void C(int i) {
        GD gd = this.C;
        if (gd.e != i) {
            if (i != 2) {
                this.e1 = -9223372036854775807L;
            }
            this.C = gd.f(i);
        }
    }

    public final void D(float f) {
        this.i1 = f;
        float f2 = f * this.x.g;
        for (int i = 0; i < 2; i++) {
            androidx.transition.V v = this.a[i];
            JE je = (JE) v.e;
            if (je.b == 1) {
                Float fValueOf = Float.valueOf(f2);
                je.c(2, fValueOf);
                JE je2 = (JE) v.f;
                if (je2 != null) {
                    je2.c(2, fValueOf);
                }
            }
        }
    }

    public final void E() {
        C2693uD c2693uD = this.q.h;
        if (c2693uD == null) {
            return;
        }
        YF yf = c2693uD.o;
        for (int i = 0; i < 2; i++) {
            if (yf.b(i)) {
                this.a[i].C();
            }
        }
    }

    public final void F(boolean z, boolean z2) {
        v(z || !this.M, false, true, false);
        this.D.e(z2 ? 1 : 0);
        this.f.b(this.t);
        this.x.a(1, this.C.l);
        C(1);
    }

    public final void G() {
        Oo oo = this.n;
        oo.b = false;
        QD qd = (QD) oo.c;
        if (qd.a) {
            qd.c(qd.zza());
            qd.a = false;
        }
        for (int i = 0; i < 2; i++) {
            androidx.transition.V v = this.a[i];
            JE je = (JE) v.e;
            if (androidx.transition.V.n(je)) {
                androidx.transition.V.o(je);
            }
            JE je2 = (JE) v.f;
            if (je2 != null && je2.h != 0) {
                androidx.transition.V.o(je2);
            }
        }
    }

    /* JADX WARN: Type inference failed for: r0v4, types: [com.google.android.gms.internal.ads.BF, java.lang.Object] */
    public final void H() {
        C2693uD c2693uD = this.q.k;
        boolean z = true;
        if (!this.J && (c2693uD == null || !c2693uD.a.o())) {
            z = false;
        }
        GD gd = this.C;
        if (z != gd.g) {
            this.C = gd.a(z);
        }
    }

    public final void I(HF hf, YF yf) {
        C2693uD c2693uD = this.q.k;
        c2693uD.getClass();
        long jV = V(c2693uD.b());
        long j = Q(this.C.a, c2693uD.g.a) ? this.k1.h : -9223372036854775807L;
        A9 a9 = this.C.a;
        float f = this.n.a().a;
        boolean z = this.C.l;
        this.f.c(new C2479pD(this.t, jV, f, this.H, j), (XF[]) yf.c);
    }

    public final void J(boolean z, int i, int i2, int i3) {
        boolean z2;
        if (!z) {
            z2 = false;
        } else if (i != -1) {
            z2 = true;
        } else {
            i = -1;
            z2 = false;
        }
        if (i == -1) {
            i3 = 2;
        } else if (i3 == 2) {
            i3 = 1;
        }
        if (i == 0) {
            i2 = 1;
        } else if (i2 == 1) {
            i2 = 0;
        }
        GD gd = this.C;
        if (gd.l == z2 && gd.n == i2 && gd.m == i3) {
            return;
        }
        this.C = gd.d(i3, i2, z2);
        M(false, false);
        C2822xD c2822xD = this.q;
        for (C2693uD c2693uD = c2822xD.h; c2693uD != null; c2693uD = c2693uD.m) {
            for (XF xf : (XF[]) c2693uD.o.c) {
            }
        }
        if (!P()) {
            G();
            K();
            c2822xD.B(this.X);
            return;
        }
        int i4 = this.C.e;
        Bo bo = this.h;
        if (i4 != 3) {
            if (i4 == 2) {
                bo.c(2);
                return;
            }
            return;
        }
        Oo oo = this.n;
        oo.b = true;
        QD qd = (QD) oo.c;
        if (!qd.a) {
            qd.c = SystemClock.elapsedRealtime();
            qd.a = true;
        }
        E();
        bo.c(2);
    }

    /* JADX WARN: Removed duplicated region for block: B:126:0x02e1  */
    /* JADX WARN: Removed duplicated region for block: B:135:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00e1  */
    /* JADX WARN: Type inference failed for: r2v29, types: [com.google.android.gms.internal.ads.eF, java.lang.Object] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void K() {
        /*
            Method dump skipped, instructions count: 776
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2436oD.K():void");
    }

    public final void L(A9 a9, C2093gF c2093gF, A9 a92, C2093gF c2093gF2, long j, boolean z) {
        if (!Q(a9, c2093gF)) {
            C2040f6 c2040f6 = c2093gF.b() ? C2040f6.d : this.C.o;
            Oo oo = this.n;
            if (oo.a().equals(c2040f6)) {
                return;
            }
            this.h.a.removeMessages(16);
            oo.b(c2040f6);
            o(this.C.o, c2040f6.a, false, false);
            return;
        }
        Object obj = c2093gF.a;
        C2303l9 c2303l9 = this.l;
        int i = a9.n(obj, c2303l9).c;
        C2518q9 c2518q9 = this.k;
        a9.e(i, c2518q9, 0L);
        D1 d1 = c2518q9.h;
        String str = Yo.a;
        SC sc = this.k1;
        sc.getClass();
        d1.getClass();
        long jT = Yo.t(-9223372036854775807L);
        sc.c = jT;
        sc.f = jT;
        sc.g = jT;
        sc.c();
        if (j != -9223372036854775807L) {
            sc.d = T(a9, obj, j);
            sc.c();
            return;
        }
        if (!Objects.equals(!a92.o() ? a92.e(a92.n(c2093gF2.a, c2303l9).c, c2518q9, 0L).a : null, c2518q9.a) || z) {
            sc.d = -9223372036854775807L;
            sc.c();
        }
    }

    public final void M(boolean z, boolean z2) {
        this.H = z;
        long jElapsedRealtime = -9223372036854775807L;
        if (z && !z2) {
            jElapsedRealtime = SystemClock.elapsedRealtime();
        }
        this.I = jElapsedRealtime;
    }

    public final boolean N() {
        if (!this.w) {
            return false;
        }
        for (int i = 0; i < 2; i++) {
            if (this.a[i].f()) {
                return true;
            }
        }
        return false;
    }

    public final boolean O() {
        C2693uD c2693uD = this.q.h;
        long j = c2693uD.g.e;
        if (c2693uD.e) {
            return j == -9223372036854775807L || this.C.r < j || !P();
        }
        return false;
    }

    public final boolean P() {
        GD gd = this.C;
        return gd.l && gd.n == 0;
    }

    public final boolean Q(A9 a9, C2093gF c2093gF) {
        if (c2093gF.b() || a9.o()) {
            return false;
        }
        int i = a9.n(c2093gF.a, this.l).c;
        C2518q9 c2518q9 = this.k;
        a9.e(i, c2518q9, 0L);
        return c2518q9.b() && c2518q9.g && c2518q9.d != -9223372036854775807L;
    }

    public final long T(A9 a9, Object obj, long j) {
        int i = a9.n(obj, this.l).c;
        C2518q9 c2518q9 = this.k;
        a9.e(i, c2518q9, 0L);
        if (c2518q9.d == -9223372036854775807L || !c2518q9.b() || !c2518q9.g) {
            return -9223372036854775807L;
        }
        long j2 = c2518q9.e;
        String str = Yo.a;
        return Yo.t((j2 == -9223372036854775807L ? System.currentTimeMillis() : j2 + SystemClock.elapsedRealtime()) - c2518q9.d) - j;
    }

    public final long U(C2693uD c2693uD) {
        if (c2693uD == null) {
            return 0L;
        }
        long jMax = c2693uD.p;
        if (c2693uD.e) {
            for (int i = 0; i < 2; i++) {
                androidx.transition.V[] vArr = this.a;
                if (vArr[i].j(c2693uD) != null) {
                    JE jeJ = vArr[i].j(c2693uD);
                    Objects.requireNonNull(jeJ);
                    long j = jeJ.m;
                    if (j == Long.MIN_VALUE) {
                        return Long.MIN_VALUE;
                    }
                    jMax = Math.max(j, jMax);
                }
            }
        }
        return jMax;
    }

    public final long V(long j) {
        C2693uD c2693uD = this.q.k;
        if (c2693uD == null) {
            return 0L;
        }
        return Math.max(0L, j - (this.X - c2693uD.p));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2636t
    public final void a(long j, long j2, C1832aG c1832aG, MediaFormat mediaFormat) {
        if (this.A) {
            Bo bo = this.h;
            bo.getClass();
            C2367mo c2367moE = Bo.e();
            c2367moE.a = bo.a.obtainMessage(37);
            c2367moE.a();
        }
    }

    /* JADX WARN: Type inference failed for: r10v6, types: [com.google.android.gms.internal.ads.eF, java.lang.Object] */
    public final long b(C2093gF c2093gF, long j, boolean z, boolean z2) {
        G();
        M(false, true);
        if (z2 || this.C.e == 3) {
            C(2);
        }
        C2822xD c2822xD = this.q;
        C2693uD c2693uD = c2822xD.h;
        C2693uD c2693uD2 = c2693uD;
        while (c2693uD2 != null && !c2093gF.equals(c2693uD2.g.a)) {
            c2693uD2 = c2693uD2.m;
        }
        if (z || c2693uD != c2693uD2 || (c2693uD2 != null && c2693uD2.p + j < 0)) {
            h();
            if (c2693uD2 != null) {
                while (c2822xD.h != c2693uD2) {
                    c2822xD.o();
                }
                c2822xD.k(c2693uD2);
                c2693uD2.p = 1000000000000L;
                j(new boolean[2], c2822xD.i.c());
                c2693uD2.h = true;
            }
        }
        f();
        if (c2693uD2 != null) {
            c2822xD.k(c2693uD2);
            if (!c2693uD2.e) {
                c2693uD2.g = c2693uD2.g.b(j);
            } else if (c2693uD2.f) {
                ?? r10 = c2693uD2.a;
                j = r10.c(j);
                r10.r(j - this.m);
            }
            x(j);
            p();
        } else {
            c2822xD.z();
            x(j);
        }
        m(false);
        this.h.c(2);
        return j;
    }

    public final Pair c(A9 a9) {
        int i;
        long j = 0;
        if (a9.o()) {
            return Pair.create(GD.t, 0L);
        }
        int iG = a9.g(this.L);
        C2518q9 c2518q9 = this.k;
        C2303l9 c2303l9 = this.l;
        Pair pairL = a9.l(c2518q9, c2303l9, iG, -9223372036854775807L);
        C2093gF c2093gFY = this.q.y(a9, pairL.first);
        long jLongValue = ((Long) pairL.second).longValue();
        if (c2093gFY.b()) {
            a9.n(c2093gFY.a, c2303l9);
            C1815a c1815aA = c2303l9.f.a(-1);
            int i2 = 0;
            while (true) {
                int[] iArr = c1815aA.d;
                if (i2 >= iArr.length || (i = iArr[i2]) == 0 || i == 1) {
                    break;
                }
                i2++;
            }
            if (-1 == i2) {
                c2303l9.f.getClass();
            }
        } else {
            j = jLongValue;
        }
        return Pair.create(c2093gFY, Long.valueOf(j));
    }

    public final GD e(C2093gF c2093gF, long j, long j2, long j3, boolean z, int i) {
        HF hf;
        YF yf;
        List list;
        Bu buJ;
        int i2;
        HF hf2;
        this.c1 = (!this.c1 && j == this.C.r && c2093gF.equals(this.C.b)) ? false : true;
        w();
        GD gd = this.C;
        HF hf3 = gd.h;
        YF yf2 = gd.i;
        List list2 = gd.j;
        if (this.r.a) {
            C2822xD c2822xD = this.q;
            C2693uD c2693uD = c2822xD.h;
            HF hf4 = c2693uD == null ? HF.d : c2693uD.n;
            YF yf3 = c2693uD == null ? this.e : c2693uD.o;
            XF[] xfArr = (XF[]) yf3.c;
            C2159hu c2159hu = new C2159hu(4);
            int length = xfArr.length;
            int i3 = 0;
            boolean z2 = false;
            while (i3 < length) {
                XF xf = xfArr[i3];
                if (xf != null) {
                    K4 k4 = xf.zza(0).k;
                    if (k4 == null) {
                        hf2 = hf4;
                        c2159hu.c(new K4(new InterfaceC2856y4[0]));
                    } else {
                        hf2 = hf4;
                        c2159hu.c(k4);
                        z2 = true;
                    }
                } else {
                    hf2 = hf4;
                }
                i3++;
                hf4 = hf2;
            }
            HF hf5 = hf4;
            int i4 = 1;
            if (z2) {
                buJ = c2159hu.j();
            } else {
                C2244ju c2244ju = AbstractC2330lu.b;
                buJ = Bu.e;
            }
            if (c2693uD != null) {
                C2736vD c2736vD = c2693uD.g;
                if (c2736vD.c != j2) {
                    c2693uD.g = c2736vD.a(j2);
                }
            }
            C2693uD c2693uD2 = c2822xD.h;
            if (c2693uD2 == c2822xD.i && c2693uD2 != null) {
                YF yf4 = c2693uD2.o;
                int i5 = 0;
                while (true) {
                    androidx.transition.V[] vArr = this.a;
                    if (i5 >= 2) {
                        break;
                    }
                    if (yf4.b(i5)) {
                        i2 = i4;
                        if (((JE) vArr[i5].e).b != i2) {
                            break;
                        }
                        ((MD[]) yf4.b)[i5].getClass();
                    } else {
                        i2 = i4;
                    }
                    i5 += i2;
                    i4 = i2;
                }
            }
            list = buJ;
            yf = yf3;
            hf = hf5;
        } else {
            if (!c2093gF.equals(gd.b)) {
                yf2 = this.e;
                hf3 = HF.d;
                list2 = Bu.e;
            }
            hf = hf3;
            yf = yf2;
            list = list2;
        }
        if (z) {
            androidx.recyclerview.widget.N n = this.D;
            if (!n.d || n.e == 5) {
                n.c = true;
                n.d = true;
                n.e = i;
            } else {
                AbstractC1795We.B(i == 5);
            }
        }
        GD gd2 = this.C;
        return gd2.c(c2093gF, j, j2, j3, V(gd2.p), hf, yf, list);
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x0030  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0035  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0047  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void f() {
        /*
            r10 = this;
            boolean r0 = r10.w
            if (r0 == 0) goto L5e
            boolean r0 = r10.N()
            if (r0 != 0) goto Lb
            goto L5e
        Lb:
            r0 = 0
            r1 = r0
        Ld:
            r2 = 2
            if (r1 >= r2) goto L57
            androidx.transition.V[] r3 = r10.a
            r3 = r3[r1]
            int r4 = r3.p()
            boolean r5 = r3.f()
            if (r5 != 0) goto L1f
            goto L4a
        L1f:
            int r5 = r3.b
            r6 = 1
            r7 = 4
            if (r5 == r7) goto L2c
            if (r5 != r2) goto L29
        L27:
            r5 = r6
            goto L2e
        L29:
            r2 = r5
            r5 = r0
            goto L2e
        L2c:
            r2 = r5
            goto L27
        L2e:
            if (r5 == 0) goto L35
            java.lang.Object r8 = r3.e
            com.google.android.gms.internal.ads.JE r8 = (com.google.android.gms.internal.ads.JE) r8
            goto L3c
        L35:
            java.lang.Object r8 = r3.f
            com.google.android.gms.internal.ads.JE r8 = (com.google.android.gms.internal.ads.JE) r8
            r8.getClass()
        L3c:
            com.google.android.gms.internal.ads.Oo r9 = r10.n
            r3.k(r8, r9)
            r3.l(r5)
            if (r2 != r7) goto L47
            goto L48
        L47:
            r6 = r0
        L48:
            r3.b = r6
        L4a:
            int r2 = r10.V
            int r3 = r3.p()
            int r4 = r4 - r3
            int r2 = r2 - r4
            r10.V = r2
            int r1 = r1 + 1
            goto Ld
        L57:
            r0 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            r10.g1 = r0
        L5e:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2436oD.f():void");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1962dF
    public final /* bridge */ /* synthetic */ void g(BF bf) {
        this.h.a(9, (InterfaceC2005eF) bf).a();
    }

    public final void h() {
        for (int i = 0; i < 2; i++) {
            androidx.transition.V[] vArr = this.a;
            int iP = vArr[i].p();
            androidx.transition.V v = vArr[i];
            JE je = (JE) v.e;
            Oo oo = this.n;
            v.k(je, oo);
            JE je2 = (JE) v.f;
            if (je2 != null) {
                boolean z = (je2.h == 0 || v.b == 3) ? false : true;
                v.k(je2, oo);
                v.l(false);
                if (z) {
                    je2.getClass();
                    je2.c(17, (JE) v.e);
                }
            }
            v.b = 0;
            t(i, false);
            this.V -= iP;
        }
        this.g1 = -9223372036854775807L;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:152:0x033b  */
    /* JADX WARN: Removed duplicated region for block: B:290:0x05d7  */
    /* JADX WARN: Removed duplicated region for block: B:291:0x05dd A[Catch: IOException -> 0x002b, zzub -> 0x002e, zzgh -> 0x0031, zzaz -> 0x0034, zzru -> 0x0037, RuntimeException -> 0x0583, zzik -> 0x0586, TRY_LEAVE, TryCatch #24 {zzik -> 0x0586, RuntimeException -> 0x0583, blocks: (B:272:0x057f, B:280:0x059a, B:281:0x05a2, B:283:0x05af, B:285:0x05bd, B:288:0x05d1, B:376:0x0738, B:378:0x073e, B:380:0x0744, B:383:0x0749, B:384:0x0754, B:386:0x0758, B:390:0x077d, B:392:0x0783, B:397:0x0791, B:398:0x0799, B:399:0x079c, B:401:0x07a5, B:448:0x0875, B:449:0x087a, B:454:0x0887, B:456:0x088f, B:457:0x0895, B:459:0x08a3, B:460:0x08bc, B:462:0x08c0, B:464:0x08c8, B:478:0x08f2, B:465:0x08cd, B:467:0x08d6, B:471:0x08df, B:477:0x08ef, B:480:0x08fc, B:482:0x0902, B:486:0x090f, B:495:0x0949, B:497:0x094f, B:499:0x0953, B:524:0x09d5, B:526:0x09e2, B:528:0x09f3, B:529:0x09fc, B:548:0x0a46, B:551:0x0a4d, B:553:0x0a51, B:558:0x0a5e, B:559:0x0a61, B:560:0x0a64, B:562:0x0a6a, B:564:0x0a73, B:566:0x0a7b, B:568:0x0a81, B:570:0x0a87, B:577:0x0aa6, B:579:0x0aac, B:583:0x0ab5, B:592:0x0acf, B:589:0x0ac8, B:591:0x0acc, B:571:0x0a8e, B:574:0x0a9c, B:575:0x0aa3, B:576:0x0aa4, B:502:0x095d, B:504:0x0961, B:506:0x0973, B:508:0x097e, B:510:0x0986, B:514:0x098f, B:516:0x0999, B:522:0x09a4, B:530:0x0a00, B:532:0x0a06, B:534:0x0a0a, B:538:0x0a13, B:540:0x0a22, B:542:0x0a28, B:544:0x0a34, B:545:0x0a39, B:546:0x0a3e, B:547:0x0a43, B:488:0x0917, B:490:0x091b, B:491:0x0935, B:493:0x093b, B:479:0x08f5, B:404:0x07ae, B:406:0x07b2, B:408:0x07b8, B:410:0x07be, B:412:0x07c8, B:415:0x07ce, B:416:0x07d1, B:418:0x07da, B:420:0x07ec, B:422:0x07f5, B:424:0x07fd, B:429:0x0809, B:431:0x0835, B:433:0x083b, B:435:0x0840, B:436:0x0848, B:438:0x084e, B:439:0x0851, B:440:0x085a, B:442:0x085e, B:444:0x0864, B:445:0x0869, B:447:0x0874, B:291:0x05dd, B:301:0x05fa, B:306:0x060b, B:310:0x061d, B:315:0x063d, B:317:0x0667, B:319:0x066b, B:323:0x067b, B:325:0x067f, B:329:0x0686, B:331:0x068e, B:333:0x06ad, B:336:0x06b6, B:338:0x06bf, B:340:0x06c5, B:341:0x06cd, B:343:0x06d3, B:321:0x0671, B:345:0x06e0, B:360:0x070e, B:362:0x0714, B:364:0x0718, B:366:0x071d, B:375:0x0735, B:372:0x072c, B:374:0x0732, B:595:0x0ad9, B:599:0x0ae2), top: B:689:0x0014 }] */
    /* JADX WARN: Removed duplicated region for block: B:295:0x05e7  */
    /* JADX WARN: Removed duplicated region for block: B:345:0x06e0 A[Catch: IOException -> 0x002b, zzub -> 0x002e, zzgh -> 0x0031, zzaz -> 0x0034, zzru -> 0x0037, RuntimeException -> 0x0583, zzik -> 0x0586, LOOP:18: B:344:0x06de->B:345:0x06e0, LOOP_END, TryCatch #24 {zzik -> 0x0586, RuntimeException -> 0x0583, blocks: (B:272:0x057f, B:280:0x059a, B:281:0x05a2, B:283:0x05af, B:285:0x05bd, B:288:0x05d1, B:376:0x0738, B:378:0x073e, B:380:0x0744, B:383:0x0749, B:384:0x0754, B:386:0x0758, B:390:0x077d, B:392:0x0783, B:397:0x0791, B:398:0x0799, B:399:0x079c, B:401:0x07a5, B:448:0x0875, B:449:0x087a, B:454:0x0887, B:456:0x088f, B:457:0x0895, B:459:0x08a3, B:460:0x08bc, B:462:0x08c0, B:464:0x08c8, B:478:0x08f2, B:465:0x08cd, B:467:0x08d6, B:471:0x08df, B:477:0x08ef, B:480:0x08fc, B:482:0x0902, B:486:0x090f, B:495:0x0949, B:497:0x094f, B:499:0x0953, B:524:0x09d5, B:526:0x09e2, B:528:0x09f3, B:529:0x09fc, B:548:0x0a46, B:551:0x0a4d, B:553:0x0a51, B:558:0x0a5e, B:559:0x0a61, B:560:0x0a64, B:562:0x0a6a, B:564:0x0a73, B:566:0x0a7b, B:568:0x0a81, B:570:0x0a87, B:577:0x0aa6, B:579:0x0aac, B:583:0x0ab5, B:592:0x0acf, B:589:0x0ac8, B:591:0x0acc, B:571:0x0a8e, B:574:0x0a9c, B:575:0x0aa3, B:576:0x0aa4, B:502:0x095d, B:504:0x0961, B:506:0x0973, B:508:0x097e, B:510:0x0986, B:514:0x098f, B:516:0x0999, B:522:0x09a4, B:530:0x0a00, B:532:0x0a06, B:534:0x0a0a, B:538:0x0a13, B:540:0x0a22, B:542:0x0a28, B:544:0x0a34, B:545:0x0a39, B:546:0x0a3e, B:547:0x0a43, B:488:0x0917, B:490:0x091b, B:491:0x0935, B:493:0x093b, B:479:0x08f5, B:404:0x07ae, B:406:0x07b2, B:408:0x07b8, B:410:0x07be, B:412:0x07c8, B:415:0x07ce, B:416:0x07d1, B:418:0x07da, B:420:0x07ec, B:422:0x07f5, B:424:0x07fd, B:429:0x0809, B:431:0x0835, B:433:0x083b, B:435:0x0840, B:436:0x0848, B:438:0x084e, B:439:0x0851, B:440:0x085a, B:442:0x085e, B:444:0x0864, B:445:0x0869, B:447:0x0874, B:291:0x05dd, B:301:0x05fa, B:306:0x060b, B:310:0x061d, B:315:0x063d, B:317:0x0667, B:319:0x066b, B:323:0x067b, B:325:0x067f, B:329:0x0686, B:331:0x068e, B:333:0x06ad, B:336:0x06b6, B:338:0x06bf, B:340:0x06c5, B:341:0x06cd, B:343:0x06d3, B:321:0x0671, B:345:0x06e0, B:360:0x070e, B:362:0x0714, B:364:0x0718, B:366:0x071d, B:375:0x0735, B:372:0x072c, B:374:0x0732, B:595:0x0ad9, B:599:0x0ae2), top: B:689:0x0014 }] */
    /* JADX WARN: Removed duplicated region for block: B:435:0x0840 A[Catch: IOException -> 0x002b, zzub -> 0x002e, zzgh -> 0x0031, zzaz -> 0x0034, zzru -> 0x0037, RuntimeException -> 0x0583, zzik -> 0x0586, LOOP:8: B:434:0x083e->B:435:0x0840, LOOP_END, TryCatch #24 {zzik -> 0x0586, RuntimeException -> 0x0583, blocks: (B:272:0x057f, B:280:0x059a, B:281:0x05a2, B:283:0x05af, B:285:0x05bd, B:288:0x05d1, B:376:0x0738, B:378:0x073e, B:380:0x0744, B:383:0x0749, B:384:0x0754, B:386:0x0758, B:390:0x077d, B:392:0x0783, B:397:0x0791, B:398:0x0799, B:399:0x079c, B:401:0x07a5, B:448:0x0875, B:449:0x087a, B:454:0x0887, B:456:0x088f, B:457:0x0895, B:459:0x08a3, B:460:0x08bc, B:462:0x08c0, B:464:0x08c8, B:478:0x08f2, B:465:0x08cd, B:467:0x08d6, B:471:0x08df, B:477:0x08ef, B:480:0x08fc, B:482:0x0902, B:486:0x090f, B:495:0x0949, B:497:0x094f, B:499:0x0953, B:524:0x09d5, B:526:0x09e2, B:528:0x09f3, B:529:0x09fc, B:548:0x0a46, B:551:0x0a4d, B:553:0x0a51, B:558:0x0a5e, B:559:0x0a61, B:560:0x0a64, B:562:0x0a6a, B:564:0x0a73, B:566:0x0a7b, B:568:0x0a81, B:570:0x0a87, B:577:0x0aa6, B:579:0x0aac, B:583:0x0ab5, B:592:0x0acf, B:589:0x0ac8, B:591:0x0acc, B:571:0x0a8e, B:574:0x0a9c, B:575:0x0aa3, B:576:0x0aa4, B:502:0x095d, B:504:0x0961, B:506:0x0973, B:508:0x097e, B:510:0x0986, B:514:0x098f, B:516:0x0999, B:522:0x09a4, B:530:0x0a00, B:532:0x0a06, B:534:0x0a0a, B:538:0x0a13, B:540:0x0a22, B:542:0x0a28, B:544:0x0a34, B:545:0x0a39, B:546:0x0a3e, B:547:0x0a43, B:488:0x0917, B:490:0x091b, B:491:0x0935, B:493:0x093b, B:479:0x08f5, B:404:0x07ae, B:406:0x07b2, B:408:0x07b8, B:410:0x07be, B:412:0x07c8, B:415:0x07ce, B:416:0x07d1, B:418:0x07da, B:420:0x07ec, B:422:0x07f5, B:424:0x07fd, B:429:0x0809, B:431:0x0835, B:433:0x083b, B:435:0x0840, B:436:0x0848, B:438:0x084e, B:439:0x0851, B:440:0x085a, B:442:0x085e, B:444:0x0864, B:445:0x0869, B:447:0x0874, B:291:0x05dd, B:301:0x05fa, B:306:0x060b, B:310:0x061d, B:315:0x063d, B:317:0x0667, B:319:0x066b, B:323:0x067b, B:325:0x067f, B:329:0x0686, B:331:0x068e, B:333:0x06ad, B:336:0x06b6, B:338:0x06bf, B:340:0x06c5, B:341:0x06cd, B:343:0x06d3, B:321:0x0671, B:345:0x06e0, B:360:0x070e, B:362:0x0714, B:364:0x0718, B:366:0x071d, B:375:0x0735, B:372:0x072c, B:374:0x0732, B:595:0x0ad9, B:599:0x0ae2), top: B:689:0x0014 }] */
    /* JADX WARN: Removed duplicated region for block: B:438:0x084e A[Catch: IOException -> 0x002b, zzub -> 0x002e, zzgh -> 0x0031, zzaz -> 0x0034, zzru -> 0x0037, RuntimeException -> 0x0583, zzik -> 0x0586, TryCatch #24 {zzik -> 0x0586, RuntimeException -> 0x0583, blocks: (B:272:0x057f, B:280:0x059a, B:281:0x05a2, B:283:0x05af, B:285:0x05bd, B:288:0x05d1, B:376:0x0738, B:378:0x073e, B:380:0x0744, B:383:0x0749, B:384:0x0754, B:386:0x0758, B:390:0x077d, B:392:0x0783, B:397:0x0791, B:398:0x0799, B:399:0x079c, B:401:0x07a5, B:448:0x0875, B:449:0x087a, B:454:0x0887, B:456:0x088f, B:457:0x0895, B:459:0x08a3, B:460:0x08bc, B:462:0x08c0, B:464:0x08c8, B:478:0x08f2, B:465:0x08cd, B:467:0x08d6, B:471:0x08df, B:477:0x08ef, B:480:0x08fc, B:482:0x0902, B:486:0x090f, B:495:0x0949, B:497:0x094f, B:499:0x0953, B:524:0x09d5, B:526:0x09e2, B:528:0x09f3, B:529:0x09fc, B:548:0x0a46, B:551:0x0a4d, B:553:0x0a51, B:558:0x0a5e, B:559:0x0a61, B:560:0x0a64, B:562:0x0a6a, B:564:0x0a73, B:566:0x0a7b, B:568:0x0a81, B:570:0x0a87, B:577:0x0aa6, B:579:0x0aac, B:583:0x0ab5, B:592:0x0acf, B:589:0x0ac8, B:591:0x0acc, B:571:0x0a8e, B:574:0x0a9c, B:575:0x0aa3, B:576:0x0aa4, B:502:0x095d, B:504:0x0961, B:506:0x0973, B:508:0x097e, B:510:0x0986, B:514:0x098f, B:516:0x0999, B:522:0x09a4, B:530:0x0a00, B:532:0x0a06, B:534:0x0a0a, B:538:0x0a13, B:540:0x0a22, B:542:0x0a28, B:544:0x0a34, B:545:0x0a39, B:546:0x0a3e, B:547:0x0a43, B:488:0x0917, B:490:0x091b, B:491:0x0935, B:493:0x093b, B:479:0x08f5, B:404:0x07ae, B:406:0x07b2, B:408:0x07b8, B:410:0x07be, B:412:0x07c8, B:415:0x07ce, B:416:0x07d1, B:418:0x07da, B:420:0x07ec, B:422:0x07f5, B:424:0x07fd, B:429:0x0809, B:431:0x0835, B:433:0x083b, B:435:0x0840, B:436:0x0848, B:438:0x084e, B:439:0x0851, B:440:0x085a, B:442:0x085e, B:444:0x0864, B:445:0x0869, B:447:0x0874, B:291:0x05dd, B:301:0x05fa, B:306:0x060b, B:310:0x061d, B:315:0x063d, B:317:0x0667, B:319:0x066b, B:323:0x067b, B:325:0x067f, B:329:0x0686, B:331:0x068e, B:333:0x06ad, B:336:0x06b6, B:338:0x06bf, B:340:0x06c5, B:341:0x06cd, B:343:0x06d3, B:321:0x0671, B:345:0x06e0, B:360:0x070e, B:362:0x0714, B:364:0x0718, B:366:0x071d, B:375:0x0735, B:372:0x072c, B:374:0x0732, B:595:0x0ad9, B:599:0x0ae2), top: B:689:0x0014 }] */
    /* JADX WARN: Removed duplicated region for block: B:442:0x085e A[Catch: IOException -> 0x002b, zzub -> 0x002e, zzgh -> 0x0031, zzaz -> 0x0034, zzru -> 0x0037, RuntimeException -> 0x0583, zzik -> 0x0586, TryCatch #24 {zzik -> 0x0586, RuntimeException -> 0x0583, blocks: (B:272:0x057f, B:280:0x059a, B:281:0x05a2, B:283:0x05af, B:285:0x05bd, B:288:0x05d1, B:376:0x0738, B:378:0x073e, B:380:0x0744, B:383:0x0749, B:384:0x0754, B:386:0x0758, B:390:0x077d, B:392:0x0783, B:397:0x0791, B:398:0x0799, B:399:0x079c, B:401:0x07a5, B:448:0x0875, B:449:0x087a, B:454:0x0887, B:456:0x088f, B:457:0x0895, B:459:0x08a3, B:460:0x08bc, B:462:0x08c0, B:464:0x08c8, B:478:0x08f2, B:465:0x08cd, B:467:0x08d6, B:471:0x08df, B:477:0x08ef, B:480:0x08fc, B:482:0x0902, B:486:0x090f, B:495:0x0949, B:497:0x094f, B:499:0x0953, B:524:0x09d5, B:526:0x09e2, B:528:0x09f3, B:529:0x09fc, B:548:0x0a46, B:551:0x0a4d, B:553:0x0a51, B:558:0x0a5e, B:559:0x0a61, B:560:0x0a64, B:562:0x0a6a, B:564:0x0a73, B:566:0x0a7b, B:568:0x0a81, B:570:0x0a87, B:577:0x0aa6, B:579:0x0aac, B:583:0x0ab5, B:592:0x0acf, B:589:0x0ac8, B:591:0x0acc, B:571:0x0a8e, B:574:0x0a9c, B:575:0x0aa3, B:576:0x0aa4, B:502:0x095d, B:504:0x0961, B:506:0x0973, B:508:0x097e, B:510:0x0986, B:514:0x098f, B:516:0x0999, B:522:0x09a4, B:530:0x0a00, B:532:0x0a06, B:534:0x0a0a, B:538:0x0a13, B:540:0x0a22, B:542:0x0a28, B:544:0x0a34, B:545:0x0a39, B:546:0x0a3e, B:547:0x0a43, B:488:0x0917, B:490:0x091b, B:491:0x0935, B:493:0x093b, B:479:0x08f5, B:404:0x07ae, B:406:0x07b2, B:408:0x07b8, B:410:0x07be, B:412:0x07c8, B:415:0x07ce, B:416:0x07d1, B:418:0x07da, B:420:0x07ec, B:422:0x07f5, B:424:0x07fd, B:429:0x0809, B:431:0x0835, B:433:0x083b, B:435:0x0840, B:436:0x0848, B:438:0x084e, B:439:0x0851, B:440:0x085a, B:442:0x085e, B:444:0x0864, B:445:0x0869, B:447:0x0874, B:291:0x05dd, B:301:0x05fa, B:306:0x060b, B:310:0x061d, B:315:0x063d, B:317:0x0667, B:319:0x066b, B:323:0x067b, B:325:0x067f, B:329:0x0686, B:331:0x068e, B:333:0x06ad, B:336:0x06b6, B:338:0x06bf, B:340:0x06c5, B:341:0x06cd, B:343:0x06d3, B:321:0x0671, B:345:0x06e0, B:360:0x070e, B:362:0x0714, B:364:0x0718, B:366:0x071d, B:375:0x0735, B:372:0x072c, B:374:0x0732, B:595:0x0ad9, B:599:0x0ae2), top: B:689:0x0014 }] */
    /* JADX WARN: Removed duplicated region for block: B:526:0x09e2 A[Catch: IOException -> 0x002b, zzub -> 0x002e, zzgh -> 0x0031, zzaz -> 0x0034, zzru -> 0x0037, RuntimeException -> 0x0583, zzik -> 0x0586, TryCatch #24 {zzik -> 0x0586, RuntimeException -> 0x0583, blocks: (B:272:0x057f, B:280:0x059a, B:281:0x05a2, B:283:0x05af, B:285:0x05bd, B:288:0x05d1, B:376:0x0738, B:378:0x073e, B:380:0x0744, B:383:0x0749, B:384:0x0754, B:386:0x0758, B:390:0x077d, B:392:0x0783, B:397:0x0791, B:398:0x0799, B:399:0x079c, B:401:0x07a5, B:448:0x0875, B:449:0x087a, B:454:0x0887, B:456:0x088f, B:457:0x0895, B:459:0x08a3, B:460:0x08bc, B:462:0x08c0, B:464:0x08c8, B:478:0x08f2, B:465:0x08cd, B:467:0x08d6, B:471:0x08df, B:477:0x08ef, B:480:0x08fc, B:482:0x0902, B:486:0x090f, B:495:0x0949, B:497:0x094f, B:499:0x0953, B:524:0x09d5, B:526:0x09e2, B:528:0x09f3, B:529:0x09fc, B:548:0x0a46, B:551:0x0a4d, B:553:0x0a51, B:558:0x0a5e, B:559:0x0a61, B:560:0x0a64, B:562:0x0a6a, B:564:0x0a73, B:566:0x0a7b, B:568:0x0a81, B:570:0x0a87, B:577:0x0aa6, B:579:0x0aac, B:583:0x0ab5, B:592:0x0acf, B:589:0x0ac8, B:591:0x0acc, B:571:0x0a8e, B:574:0x0a9c, B:575:0x0aa3, B:576:0x0aa4, B:502:0x095d, B:504:0x0961, B:506:0x0973, B:508:0x097e, B:510:0x0986, B:514:0x098f, B:516:0x0999, B:522:0x09a4, B:530:0x0a00, B:532:0x0a06, B:534:0x0a0a, B:538:0x0a13, B:540:0x0a22, B:542:0x0a28, B:544:0x0a34, B:545:0x0a39, B:546:0x0a3e, B:547:0x0a43, B:488:0x0917, B:490:0x091b, B:491:0x0935, B:493:0x093b, B:479:0x08f5, B:404:0x07ae, B:406:0x07b2, B:408:0x07b8, B:410:0x07be, B:412:0x07c8, B:415:0x07ce, B:416:0x07d1, B:418:0x07da, B:420:0x07ec, B:422:0x07f5, B:424:0x07fd, B:429:0x0809, B:431:0x0835, B:433:0x083b, B:435:0x0840, B:436:0x0848, B:438:0x084e, B:439:0x0851, B:440:0x085a, B:442:0x085e, B:444:0x0864, B:445:0x0869, B:447:0x0874, B:291:0x05dd, B:301:0x05fa, B:306:0x060b, B:310:0x061d, B:315:0x063d, B:317:0x0667, B:319:0x066b, B:323:0x067b, B:325:0x067f, B:329:0x0686, B:331:0x068e, B:333:0x06ad, B:336:0x06b6, B:338:0x06bf, B:340:0x06c5, B:341:0x06cd, B:343:0x06d3, B:321:0x0671, B:345:0x06e0, B:360:0x070e, B:362:0x0714, B:364:0x0718, B:366:0x071d, B:375:0x0735, B:372:0x072c, B:374:0x0732, B:595:0x0ad9, B:599:0x0ae2), top: B:689:0x0014 }] */
    /* JADX WARN: Removed duplicated region for block: B:530:0x0a00 A[Catch: IOException -> 0x002b, zzub -> 0x002e, zzgh -> 0x0031, zzaz -> 0x0034, zzru -> 0x0037, RuntimeException -> 0x0583, zzik -> 0x0586, TryCatch #24 {zzik -> 0x0586, RuntimeException -> 0x0583, blocks: (B:272:0x057f, B:280:0x059a, B:281:0x05a2, B:283:0x05af, B:285:0x05bd, B:288:0x05d1, B:376:0x0738, B:378:0x073e, B:380:0x0744, B:383:0x0749, B:384:0x0754, B:386:0x0758, B:390:0x077d, B:392:0x0783, B:397:0x0791, B:398:0x0799, B:399:0x079c, B:401:0x07a5, B:448:0x0875, B:449:0x087a, B:454:0x0887, B:456:0x088f, B:457:0x0895, B:459:0x08a3, B:460:0x08bc, B:462:0x08c0, B:464:0x08c8, B:478:0x08f2, B:465:0x08cd, B:467:0x08d6, B:471:0x08df, B:477:0x08ef, B:480:0x08fc, B:482:0x0902, B:486:0x090f, B:495:0x0949, B:497:0x094f, B:499:0x0953, B:524:0x09d5, B:526:0x09e2, B:528:0x09f3, B:529:0x09fc, B:548:0x0a46, B:551:0x0a4d, B:553:0x0a51, B:558:0x0a5e, B:559:0x0a61, B:560:0x0a64, B:562:0x0a6a, B:564:0x0a73, B:566:0x0a7b, B:568:0x0a81, B:570:0x0a87, B:577:0x0aa6, B:579:0x0aac, B:583:0x0ab5, B:592:0x0acf, B:589:0x0ac8, B:591:0x0acc, B:571:0x0a8e, B:574:0x0a9c, B:575:0x0aa3, B:576:0x0aa4, B:502:0x095d, B:504:0x0961, B:506:0x0973, B:508:0x097e, B:510:0x0986, B:514:0x098f, B:516:0x0999, B:522:0x09a4, B:530:0x0a00, B:532:0x0a06, B:534:0x0a0a, B:538:0x0a13, B:540:0x0a22, B:542:0x0a28, B:544:0x0a34, B:545:0x0a39, B:546:0x0a3e, B:547:0x0a43, B:488:0x0917, B:490:0x091b, B:491:0x0935, B:493:0x093b, B:479:0x08f5, B:404:0x07ae, B:406:0x07b2, B:408:0x07b8, B:410:0x07be, B:412:0x07c8, B:415:0x07ce, B:416:0x07d1, B:418:0x07da, B:420:0x07ec, B:422:0x07f5, B:424:0x07fd, B:429:0x0809, B:431:0x0835, B:433:0x083b, B:435:0x0840, B:436:0x0848, B:438:0x084e, B:439:0x0851, B:440:0x085a, B:442:0x085e, B:444:0x0864, B:445:0x0869, B:447:0x0874, B:291:0x05dd, B:301:0x05fa, B:306:0x060b, B:310:0x061d, B:315:0x063d, B:317:0x0667, B:319:0x066b, B:323:0x067b, B:325:0x067f, B:329:0x0686, B:331:0x068e, B:333:0x06ad, B:336:0x06b6, B:338:0x06bf, B:340:0x06c5, B:341:0x06cd, B:343:0x06d3, B:321:0x0671, B:345:0x06e0, B:360:0x070e, B:362:0x0714, B:364:0x0718, B:366:0x071d, B:375:0x0735, B:372:0x072c, B:374:0x0732, B:595:0x0ad9, B:599:0x0ae2), top: B:689:0x0014 }] */
    /* JADX WARN: Removed duplicated region for block: B:532:0x0a06 A[Catch: IOException -> 0x002b, zzub -> 0x002e, zzgh -> 0x0031, zzaz -> 0x0034, zzru -> 0x0037, RuntimeException -> 0x0583, zzik -> 0x0586, TryCatch #24 {zzik -> 0x0586, RuntimeException -> 0x0583, blocks: (B:272:0x057f, B:280:0x059a, B:281:0x05a2, B:283:0x05af, B:285:0x05bd, B:288:0x05d1, B:376:0x0738, B:378:0x073e, B:380:0x0744, B:383:0x0749, B:384:0x0754, B:386:0x0758, B:390:0x077d, B:392:0x0783, B:397:0x0791, B:398:0x0799, B:399:0x079c, B:401:0x07a5, B:448:0x0875, B:449:0x087a, B:454:0x0887, B:456:0x088f, B:457:0x0895, B:459:0x08a3, B:460:0x08bc, B:462:0x08c0, B:464:0x08c8, B:478:0x08f2, B:465:0x08cd, B:467:0x08d6, B:471:0x08df, B:477:0x08ef, B:480:0x08fc, B:482:0x0902, B:486:0x090f, B:495:0x0949, B:497:0x094f, B:499:0x0953, B:524:0x09d5, B:526:0x09e2, B:528:0x09f3, B:529:0x09fc, B:548:0x0a46, B:551:0x0a4d, B:553:0x0a51, B:558:0x0a5e, B:559:0x0a61, B:560:0x0a64, B:562:0x0a6a, B:564:0x0a73, B:566:0x0a7b, B:568:0x0a81, B:570:0x0a87, B:577:0x0aa6, B:579:0x0aac, B:583:0x0ab5, B:592:0x0acf, B:589:0x0ac8, B:591:0x0acc, B:571:0x0a8e, B:574:0x0a9c, B:575:0x0aa3, B:576:0x0aa4, B:502:0x095d, B:504:0x0961, B:506:0x0973, B:508:0x097e, B:510:0x0986, B:514:0x098f, B:516:0x0999, B:522:0x09a4, B:530:0x0a00, B:532:0x0a06, B:534:0x0a0a, B:538:0x0a13, B:540:0x0a22, B:542:0x0a28, B:544:0x0a34, B:545:0x0a39, B:546:0x0a3e, B:547:0x0a43, B:488:0x0917, B:490:0x091b, B:491:0x0935, B:493:0x093b, B:479:0x08f5, B:404:0x07ae, B:406:0x07b2, B:408:0x07b8, B:410:0x07be, B:412:0x07c8, B:415:0x07ce, B:416:0x07d1, B:418:0x07da, B:420:0x07ec, B:422:0x07f5, B:424:0x07fd, B:429:0x0809, B:431:0x0835, B:433:0x083b, B:435:0x0840, B:436:0x0848, B:438:0x084e, B:439:0x0851, B:440:0x085a, B:442:0x085e, B:444:0x0864, B:445:0x0869, B:447:0x0874, B:291:0x05dd, B:301:0x05fa, B:306:0x060b, B:310:0x061d, B:315:0x063d, B:317:0x0667, B:319:0x066b, B:323:0x067b, B:325:0x067f, B:329:0x0686, B:331:0x068e, B:333:0x06ad, B:336:0x06b6, B:338:0x06bf, B:340:0x06c5, B:341:0x06cd, B:343:0x06d3, B:321:0x0671, B:345:0x06e0, B:360:0x070e, B:362:0x0714, B:364:0x0718, B:366:0x071d, B:375:0x0735, B:372:0x072c, B:374:0x0732, B:595:0x0ad9, B:599:0x0ae2), top: B:689:0x0014 }] */
    /* JADX WARN: Removed duplicated region for block: B:540:0x0a22 A[Catch: IOException -> 0x002b, zzub -> 0x002e, zzgh -> 0x0031, zzaz -> 0x0034, zzru -> 0x0037, RuntimeException -> 0x0583, zzik -> 0x0586, TryCatch #24 {zzik -> 0x0586, RuntimeException -> 0x0583, blocks: (B:272:0x057f, B:280:0x059a, B:281:0x05a2, B:283:0x05af, B:285:0x05bd, B:288:0x05d1, B:376:0x0738, B:378:0x073e, B:380:0x0744, B:383:0x0749, B:384:0x0754, B:386:0x0758, B:390:0x077d, B:392:0x0783, B:397:0x0791, B:398:0x0799, B:399:0x079c, B:401:0x07a5, B:448:0x0875, B:449:0x087a, B:454:0x0887, B:456:0x088f, B:457:0x0895, B:459:0x08a3, B:460:0x08bc, B:462:0x08c0, B:464:0x08c8, B:478:0x08f2, B:465:0x08cd, B:467:0x08d6, B:471:0x08df, B:477:0x08ef, B:480:0x08fc, B:482:0x0902, B:486:0x090f, B:495:0x0949, B:497:0x094f, B:499:0x0953, B:524:0x09d5, B:526:0x09e2, B:528:0x09f3, B:529:0x09fc, B:548:0x0a46, B:551:0x0a4d, B:553:0x0a51, B:558:0x0a5e, B:559:0x0a61, B:560:0x0a64, B:562:0x0a6a, B:564:0x0a73, B:566:0x0a7b, B:568:0x0a81, B:570:0x0a87, B:577:0x0aa6, B:579:0x0aac, B:583:0x0ab5, B:592:0x0acf, B:589:0x0ac8, B:591:0x0acc, B:571:0x0a8e, B:574:0x0a9c, B:575:0x0aa3, B:576:0x0aa4, B:502:0x095d, B:504:0x0961, B:506:0x0973, B:508:0x097e, B:510:0x0986, B:514:0x098f, B:516:0x0999, B:522:0x09a4, B:530:0x0a00, B:532:0x0a06, B:534:0x0a0a, B:538:0x0a13, B:540:0x0a22, B:542:0x0a28, B:544:0x0a34, B:545:0x0a39, B:546:0x0a3e, B:547:0x0a43, B:488:0x0917, B:490:0x091b, B:491:0x0935, B:493:0x093b, B:479:0x08f5, B:404:0x07ae, B:406:0x07b2, B:408:0x07b8, B:410:0x07be, B:412:0x07c8, B:415:0x07ce, B:416:0x07d1, B:418:0x07da, B:420:0x07ec, B:422:0x07f5, B:424:0x07fd, B:429:0x0809, B:431:0x0835, B:433:0x083b, B:435:0x0840, B:436:0x0848, B:438:0x084e, B:439:0x0851, B:440:0x085a, B:442:0x085e, B:444:0x0864, B:445:0x0869, B:447:0x0874, B:291:0x05dd, B:301:0x05fa, B:306:0x060b, B:310:0x061d, B:315:0x063d, B:317:0x0667, B:319:0x066b, B:323:0x067b, B:325:0x067f, B:329:0x0686, B:331:0x068e, B:333:0x06ad, B:336:0x06b6, B:338:0x06bf, B:340:0x06c5, B:341:0x06cd, B:343:0x06d3, B:321:0x0671, B:345:0x06e0, B:360:0x070e, B:362:0x0714, B:364:0x0718, B:366:0x071d, B:375:0x0735, B:372:0x072c, B:374:0x0732, B:595:0x0ad9, B:599:0x0ae2), top: B:689:0x0014 }] */
    /* JADX WARN: Removed duplicated region for block: B:550:0x0a4c  */
    /* JADX WARN: Removed duplicated region for block: B:576:0x0aa4 A[Catch: IOException -> 0x002b, zzub -> 0x002e, zzgh -> 0x0031, zzaz -> 0x0034, zzru -> 0x0037, RuntimeException -> 0x0583, zzik -> 0x0586, TryCatch #24 {zzik -> 0x0586, RuntimeException -> 0x0583, blocks: (B:272:0x057f, B:280:0x059a, B:281:0x05a2, B:283:0x05af, B:285:0x05bd, B:288:0x05d1, B:376:0x0738, B:378:0x073e, B:380:0x0744, B:383:0x0749, B:384:0x0754, B:386:0x0758, B:390:0x077d, B:392:0x0783, B:397:0x0791, B:398:0x0799, B:399:0x079c, B:401:0x07a5, B:448:0x0875, B:449:0x087a, B:454:0x0887, B:456:0x088f, B:457:0x0895, B:459:0x08a3, B:460:0x08bc, B:462:0x08c0, B:464:0x08c8, B:478:0x08f2, B:465:0x08cd, B:467:0x08d6, B:471:0x08df, B:477:0x08ef, B:480:0x08fc, B:482:0x0902, B:486:0x090f, B:495:0x0949, B:497:0x094f, B:499:0x0953, B:524:0x09d5, B:526:0x09e2, B:528:0x09f3, B:529:0x09fc, B:548:0x0a46, B:551:0x0a4d, B:553:0x0a51, B:558:0x0a5e, B:559:0x0a61, B:560:0x0a64, B:562:0x0a6a, B:564:0x0a73, B:566:0x0a7b, B:568:0x0a81, B:570:0x0a87, B:577:0x0aa6, B:579:0x0aac, B:583:0x0ab5, B:592:0x0acf, B:589:0x0ac8, B:591:0x0acc, B:571:0x0a8e, B:574:0x0a9c, B:575:0x0aa3, B:576:0x0aa4, B:502:0x095d, B:504:0x0961, B:506:0x0973, B:508:0x097e, B:510:0x0986, B:514:0x098f, B:516:0x0999, B:522:0x09a4, B:530:0x0a00, B:532:0x0a06, B:534:0x0a0a, B:538:0x0a13, B:540:0x0a22, B:542:0x0a28, B:544:0x0a34, B:545:0x0a39, B:546:0x0a3e, B:547:0x0a43, B:488:0x0917, B:490:0x091b, B:491:0x0935, B:493:0x093b, B:479:0x08f5, B:404:0x07ae, B:406:0x07b2, B:408:0x07b8, B:410:0x07be, B:412:0x07c8, B:415:0x07ce, B:416:0x07d1, B:418:0x07da, B:420:0x07ec, B:422:0x07f5, B:424:0x07fd, B:429:0x0809, B:431:0x0835, B:433:0x083b, B:435:0x0840, B:436:0x0848, B:438:0x084e, B:439:0x0851, B:440:0x085a, B:442:0x085e, B:444:0x0864, B:445:0x0869, B:447:0x0874, B:291:0x05dd, B:301:0x05fa, B:306:0x060b, B:310:0x061d, B:315:0x063d, B:317:0x0667, B:319:0x066b, B:323:0x067b, B:325:0x067f, B:329:0x0686, B:331:0x068e, B:333:0x06ad, B:336:0x06b6, B:338:0x06bf, B:340:0x06c5, B:341:0x06cd, B:343:0x06d3, B:321:0x0671, B:345:0x06e0, B:360:0x070e, B:362:0x0714, B:364:0x0718, B:366:0x071d, B:375:0x0735, B:372:0x072c, B:374:0x0732, B:595:0x0ad9, B:599:0x0ae2), top: B:689:0x0014 }] */
    /* JADX WARN: Removed duplicated region for block: B:603:0x0b02  */
    /* JADX WARN: Removed duplicated region for block: B:613:0x0b3c  */
    /* JADX WARN: Removed duplicated region for block: B:622:0x0b59  */
    /* JADX WARN: Removed duplicated region for block: B:629:0x0b72  */
    /* JADX WARN: Removed duplicated region for block: B:648:0x0bd3  */
    /* JADX WARN: Removed duplicated region for block: B:650:0x0bd7  */
    /* JADX WARN: Removed duplicated region for block: B:653:0x0be1  */
    /* JADX WARN: Type inference failed for: r0v101, types: [com.google.android.gms.internal.ads.eF, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r3v37, types: [com.google.android.gms.internal.ads.eF, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r3v93, types: [com.google.android.gms.internal.ads.eF, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r5v14, types: [com.google.android.gms.internal.ads.eF, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r5v26, types: [com.google.android.gms.internal.ads.eF, java.lang.Object] */
    @Override // android.os.Handler.Callback
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean handleMessage(android.os.Message r34) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 3250
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2436oD.handleMessage(android.os.Message):boolean");
    }

    public final void i(C2693uD c2693uD, int i, boolean z, long j) {
        androidx.transition.V v = this.a[i];
        if (v.h()) {
            return;
        }
        boolean z2 = c2693uD == this.q.h;
        YF yf = c2693uD.o;
        MD md = ((MD[]) yf.b)[i];
        XF xf = ((XF[]) yf.c)[i];
        boolean z3 = P() && this.C.e == 3;
        boolean z4 = !z && z3;
        this.V++;
        AF af = c2693uD.c[i];
        long j2 = c2693uD.p;
        C2736vD c2736vD = c2693uD.g;
        int iG = xf != null ? xf.g() : 0;
        C1832aG[] c1832aGArr = new C1832aG[iG];
        for (int i2 = 0; i2 < iG; i2++) {
            xf.getClass();
            c1832aGArr[i2] = xf.zza(i2);
        }
        int i3 = v.b;
        C2093gF c2093gF = c2736vD.a;
        Oo oo = this.n;
        if (i3 == 0 || i3 == 2 || i3 == 4) {
            v.c = true;
            JE je = (JE) v.e;
            AbstractC1795We.L(je.h == 0);
            je.d = md;
            je.q = c2093gF;
            je.h = 1;
            je.i0(z4, z2);
            je.j(c1832aGArr, af, j, j2, c2093gF);
            je.n = false;
            je.l = j;
            je.m = j;
            je.j0(j, z4);
            oo.c(je);
        } else {
            v.d = true;
            JE je2 = (JE) v.f;
            je2.getClass();
            AbstractC1795We.L(je2.h == 0);
            je2.d = md;
            je2.q = c2093gF;
            je2.h = 1;
            je2.i0(z4, z2);
            je2.j(c1832aGArr, af, j, j2, c2093gF);
            je2.n = false;
            je2.l = j;
            je2.m = j;
            je2.j0(j, z4);
            oo.c(je2);
        }
        C2307lD c2307lD = new C2307lD();
        JE jeJ = v.j(c2693uD);
        jeJ.getClass();
        jeJ.c(11, c2307lD);
        if (z3 && z2) {
            v.C();
        }
    }

    public final void j(boolean[] zArr, long j) {
        androidx.transition.V[] vArr;
        long j2;
        C2693uD c2693uD = this.q.i;
        YF yf = c2693uD.o;
        int i = 0;
        while (true) {
            vArr = this.a;
            if (i >= 2) {
                break;
            }
            if (!yf.b(i)) {
                vArr[i].x();
            }
            i++;
        }
        int i2 = 0;
        while (i2 < 2) {
            if (yf.b(i2) && vArr[i2].j(c2693uD) == null) {
                j2 = j;
                i(c2693uD, i2, zArr[i2], j2);
            } else {
                j2 = j;
            }
            i2++;
            j = j2;
        }
    }

    public final void k(int i, IOException iOException) {
        zzik zzikVar = new zzik(0, iOException, i);
        C2693uD c2693uD = this.q.h;
        if (c2693uD != null) {
            zzikVar = zzikVar.a(c2693uD.g.a);
        }
        AbstractC2096gb.A("ExoPlayerImplInternal", "Playback error", zzikVar);
        F(false, false);
        this.C = this.C.e(zzikVar);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1962dF
    public final void l(InterfaceC2005eF interfaceC2005eF) {
        this.h.a(8, interfaceC2005eF).a();
    }

    public final void m(boolean z) {
        C2693uD c2693uD = this.q.k;
        C2093gF c2093gF = c2693uD == null ? this.C.b : c2693uD.g.a;
        boolean zEquals = this.C.k.equals(c2093gF);
        if (!zEquals) {
            this.C = this.C.b(c2093gF);
        }
        GD gd = this.C;
        gd.p = c2693uD == null ? gd.r : c2693uD.b();
        GD gd2 = this.C;
        gd2.q = V(gd2.p);
        if ((!zEquals || z) && c2693uD != null && c2693uD.e) {
            I(c2693uD.n, c2693uD.o);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:185:0x0311  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x005a  */
    /* JADX WARN: Removed duplicated region for block: B:205:0x0348  */
    /* JADX WARN: Removed duplicated region for block: B:206:0x034b  */
    /* JADX WARN: Removed duplicated region for block: B:211:0x0360  */
    /* JADX WARN: Removed duplicated region for block: B:219:0x037e  */
    /* JADX WARN: Removed duplicated region for block: B:222:0x038a  */
    /* JADX WARN: Removed duplicated region for block: B:224:0x0390  */
    /* JADX WARN: Removed duplicated region for block: B:228:0x03b1  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0061  */
    /* JADX WARN: Removed duplicated region for block: B:233:0x03c8  */
    /* JADX WARN: Removed duplicated region for block: B:234:0x03cb  */
    /* JADX WARN: Removed duplicated region for block: B:237:0x03d6  */
    /* JADX WARN: Removed duplicated region for block: B:239:0x03de  */
    /* JADX WARN: Removed duplicated region for block: B:247:0x03fd  */
    /* JADX WARN: Removed duplicated region for block: B:250:0x040a  */
    /* JADX WARN: Removed duplicated region for block: B:252:0x040f  */
    /* JADX WARN: Removed duplicated region for block: B:256:0x0430  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00b6  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x015b  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0178  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x01b0  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x01bb  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x01c3  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x01ca  */
    /* JADX WARN: Type inference failed for: r8v19 */
    /* JADX WARN: Type inference failed for: r8v20, types: [int] */
    /* JADX WARN: Type inference failed for: r8v21 */
    /* JADX WARN: Type inference failed for: r8v22 */
    /* JADX WARN: Type inference failed for: r8v23 */
    /* JADX WARN: Type inference failed for: r8v24 */
    /* JADX WARN: Type inference failed for: r8v25 */
    /* JADX WARN: Type inference failed for: r8v28 */
    /* JADX WARN: Type inference failed for: r8v30 */
    /* JADX WARN: Type inference failed for: r8v34 */
    /* JADX WARN: Type inference failed for: r8v37 */
    /* JADX WARN: Type inference failed for: r8v38 */
    /* JADX WARN: Type inference failed for: r8v39 */
    /* JADX WARN: Type inference failed for: r8v40 */
    /* JADX WARN: Type inference failed for: r8v41 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void n(com.google.android.gms.internal.ads.A9 r28, boolean r29) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 1085
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2436oD.n(com.google.android.gms.internal.ads.A9, boolean):void");
    }

    public final void o(C2040f6 c2040f6, float f, boolean z, boolean z2) {
        int i;
        if (z) {
            if (z2) {
                this.D.e(1);
            }
            GD gd = this.C;
            this.C = new GD(gd.a, gd.b, gd.c, gd.d, gd.e, gd.f, gd.g, gd.h, gd.i, gd.j, gd.k, gd.l, gd.m, gd.n, c2040f6, gd.p, gd.q, gd.r, gd.s);
        }
        float f2 = c2040f6.a;
        C2693uD c2693uD = this.q.h;
        while (true) {
            i = 0;
            if (c2693uD == null) {
                break;
            }
            XF[] xfArr = (XF[]) c2693uD.o.c;
            int length = xfArr.length;
            while (i < length) {
                XF xf = xfArr[i];
                i++;
            }
            c2693uD = c2693uD.m;
        }
        androidx.transition.V[] vArr = this.a;
        while (i < 2) {
            androidx.transition.V v = vArr[i];
            ((JE) v.e).k(f, f2);
            JE je = (JE) v.f;
            if (je != null) {
                je.k(f, f2);
            }
            i++;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:40:0x00d2  */
    /* JADX WARN: Type inference failed for: r1v2, types: [com.google.android.gms.internal.ads.BF, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r8v1, types: [com.google.android.gms.internal.ads.BF, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r8v7, types: [com.google.android.gms.internal.ads.eF, java.lang.Object] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void p() {
        /*
            Method dump skipped, instructions count: 223
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2436oD.p():void");
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [com.google.android.gms.internal.ads.BF, com.google.android.gms.internal.ads.eF, java.lang.Object] */
    public final void q() {
        boolean z;
        C2822xD c2822xD = this.q;
        c2822xD.A();
        C2693uD c2693uD = c2822xD.l;
        if (c2693uD != null) {
            if (!c2693uD.d || c2693uD.e) {
                ?? r1 = c2693uD.a;
                if (r1.o()) {
                    return;
                }
                A9 a9 = this.C.a;
                if (c2693uD.e) {
                    r1.b();
                }
                if (this.f.zzi()) {
                    if (!c2693uD.d) {
                        C2736vD c2736vD = c2693uD.g;
                        c2693uD.d = true;
                        r1.e(this, c2736vD.b);
                        return;
                    }
                    C2564rD c2564rD = new C2564rD();
                    c2564rD.a = this.X - c2693uD.p;
                    float f = this.n.a().a;
                    AbstractC1795We.B(f > DefinitionKt.NO_Float_VALUE || f == -3.4028235E38f);
                    c2564rD.b = f;
                    long j = this.I;
                    if (j >= 0) {
                        z = true;
                    } else if (j == -9223372036854775807L) {
                        j = -9223372036854775807L;
                        z = true;
                    } else {
                        z = false;
                    }
                    AbstractC1795We.B(z);
                    c2564rD.c = j;
                    C2607sD c2607sD = new C2607sD(c2564rD);
                    AbstractC1795We.L(c2693uD.m == null);
                    r1.k(c2607sD);
                }
            }
        }
    }

    public final void r() {
        androidx.recyclerview.widget.N n = this.D;
        GD gd = this.C;
        boolean z = n.c | (((GD) n.f) != gd);
        n.c = z;
        n.f = gd;
        if (z) {
            C2221jD c2221jD = (C2221jD) this.j1.b;
            c2221jD.getClass();
            c2221jD.k.b(new RunnableC2793wl(17, c2221jD, n));
            this.D = new androidx.recyclerview.widget.N(this.C);
        }
    }

    public final void s(int i) {
        androidx.transition.V v = this.a[i];
        try {
            C2693uD c2693uD = this.q.h;
            if (c2693uD == null) {
                throw null;
            }
            JE jeJ = v.j(c2693uD);
            jeJ.getClass();
            AF af = jeJ.i;
            af.getClass();
            af.j();
        } catch (IOException | RuntimeException e) {
            int i2 = ((JE) v.e).b;
            throw e;
        }
    }

    public final void t(int i, boolean z) {
        boolean[] zArr = this.c;
        if (zArr[i] != z) {
            zArr[i] = z;
            this.v.b(new androidx.core.provider.a(this, i, z));
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:77:0x016a  */
    /* JADX WARN: Removed duplicated region for block: B:90:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void u() {
        /*
            Method dump skipped, instructions count: 374
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2436oD.u():void");
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x0085  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00b4 A[PHI: r3 r7 r9
  0x00b4: PHI (r3v2 com.google.android.gms.internal.ads.gF) = (r3v1 com.google.android.gms.internal.ads.gF), (r3v14 com.google.android.gms.internal.ads.gF) binds: [B:30:0x0089, B:32:0x00ae] A[DONT_GENERATE, DONT_INLINE]
  0x00b4: PHI (r7v4 long) = (r7v3 long), (r7v17 long) binds: [B:30:0x0089, B:32:0x00ae] A[DONT_GENERATE, DONT_INLINE]
  0x00b4: PHI (r9v2 long) = (r9v1 long), (r9v9 long) binds: [B:30:0x0089, B:32:0x00ae] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0113  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void v(boolean r34, boolean r35, boolean r36, boolean r37) {
        /*
            Method dump skipped, instructions count: 431
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2436oD.v(boolean, boolean, boolean, boolean):void");
    }

    public final void w() {
        C2693uD c2693uD = this.q.h;
        boolean z = false;
        if (c2693uD != null && c2693uD.g.g && this.F) {
            z = true;
        }
        this.G = z;
    }

    public final void x(long j) {
        C2693uD c2693uD = this.q.h;
        long j2 = j + (c2693uD == null ? 1000000000000L : c2693uD.p);
        this.X = j2;
        ((QD) this.n.c).c(j2);
        for (int i = 0; i < 2; i++) {
            androidx.transition.V v = this.a[i];
            long j3 = this.X;
            JE jeJ = v.j(c2693uD);
            if (jeJ != null) {
                jeJ.n = false;
                jeJ.l = j3;
                jeJ.m = j3;
                jeJ.j0(j3, false);
            }
        }
        for (C2693uD c2693uD2 = r0.h; c2693uD2 != null; c2693uD2 = c2693uD2.m) {
            for (XF xf : (XF[]) c2693uD2.o.c) {
            }
        }
    }

    public final void y(A9 a9, A9 a92) {
        if (a9.o() && a92.o()) {
            return;
        }
        ArrayList arrayList = this.o;
        int size = arrayList.size() - 1;
        if (size < 0) {
            Collections.sort(arrayList);
        } else {
            arrayList.get(size).getClass();
            throw new ClassCastException();
        }
    }

    public final void z(long j) {
        this.h.a.sendEmptyMessageAtTime(2, j + ((this.C.e != 3 || P()) ? l1 : 1000L));
    }
}
