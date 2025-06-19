package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Pair;
import android.util.SparseBooleanArray;
import android.view.Surface;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.facebook.internal.C1549d;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;

/* renamed from: com.google.android.gms.internal.ads.jD, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2221jD extends AbstractC2863yB {
    public static final /* synthetic */ int i1 = 0;
    public final com.quizlet.data.interactor.progress.c A;
    public int B;
    public int C;
    public boolean D;
    public final OD E;
    public final C1829aD F;
    public C2816x7 G;
    public C2082g4 H;
    public Surface I;
    public Surface J;
    public final int K;
    public Pn L;
    public final Wl M;
    public float V;
    public boolean W;
    public final boolean X;
    public boolean Y;
    public final int Z;
    public final YF c;
    public C2082g4 c1;
    public final C2816x7 d;
    public GD d1;
    public final C1973dj e;
    public int e1;
    public final Context f;
    public long f1;
    public final PD g;
    public final C2586rt g1;
    public final JE[] h;
    public CF h1;
    public final JE[] i;
    public final VF j;
    public final Bo k;
    public final C2436oD l;
    public final com.amazon.aps.ads.privacy.a m;
    public final CopyOnWriteArraySet n;
    public final C2303l9 o;
    public final ArrayList p;
    public final boolean q;
    public final WD r;
    public final Looper s;
    public final C2050fG t;
    public final C1847ao u;
    public final SurfaceHolderCallbackC2091gD v;
    public final C1946d w;
    public final androidx.camera.camera2.internal.compat.workaround.e x;
    public final androidx.camera.camera2.internal.compat.workaround.e y;
    public final long z;

    static {
        E3.a("media3.exoplayer");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2221jD(ZC zc, PD pd) {
        super(5);
        int i = 1;
        boolean z = false;
        int i2 = 5;
        this.e = new C1973dj();
        try {
            AbstractC2096gb.F("ExoPlayerImpl", "Init " + Integer.toHexString(System.identityHashCode(this)) + " [AndroidXMedia3/1.6.1] [" + Yo.a + "]");
            Context context = zc.a;
            Looper looper = zc.i;
            this.f = context.getApplicationContext();
            C2853y1 c2853y1 = zc.h;
            C1847ao c1847ao = zc.b;
            c2853y1.getClass();
            this.r = new WD(c1847ao);
            this.Z = zc.j;
            this.M = zc.k;
            this.K = zc.l;
            this.W = false;
            this.z = zc.p;
            SurfaceHolderCallbackC2091gD surfaceHolderCallbackC2091gD = new SurfaceHolderCallbackC2091gD(this);
            this.v = surfaceHolderCallbackC2091gD;
            this.w = new C1946d(1);
            this.h = C2143he.t((C2143he) ((Ts) zc.c.b).b, new Handler(looper), surfaceHolderCallbackC2091gD, surfaceHolderCallbackC2091gD);
            this.i = new JE[2];
            int i3 = 0;
            while (true) {
                JE[] jeArr = this.i;
                int length = jeArr.length;
                if (i3 >= 2) {
                    break;
                }
                JE je = this.h[i3];
                jeArr[i3] = null;
                i3++;
            }
            this.j = (VF) zc.e.zza();
            Context context2 = zc.d.a;
            new S();
            new Ex(context2);
            HashMap map = new HashMap();
            HashMap map2 = new HashMap();
            map.clear();
            map2.clear();
            this.t = C2050fG.a(zc.g.a);
            this.q = zc.m;
            this.E = zc.n;
            this.s = looper;
            this.u = c1847ao;
            this.g = pd;
            this.m = new com.amazon.aps.ads.privacy.a(looper, c1847ao, new C2047fD(i));
            this.n = new CopyOnWriteArraySet();
            this.p = new ArrayList();
            this.h1 = new CF();
            this.F = C1829aD.a;
            int length2 = this.h.length;
            this.c = new YF(new MD[2], new XF[2], C2697ub.b, null);
            this.o = new C2303l9();
            SparseBooleanArray sparseBooleanArray = new SparseBooleanArray();
            int[] iArr = {1, 2, 3, 13, 14, 15, 16, 17, 18, 19, 31, 20, 30, 21, 35, 22, 24, 27, 28, 32};
            for (int i4 = 0; i4 < 20; i4++) {
                int i5 = iArr[i4];
                AbstractC1795We.L(!false);
                sparseBooleanArray.append(i5, true);
            }
            this.j.getClass();
            AbstractC1795We.L(!false);
            sparseBooleanArray.append(29, true);
            AbstractC1795We.L(!false);
            C2049fF c2049fF = new C2049fF(sparseBooleanArray);
            this.d = new C2816x7(c2049fF);
            SparseBooleanArray sparseBooleanArray2 = new SparseBooleanArray();
            for (int i6 = 0; i6 < c2049fF.a.size(); i6++) {
                int iA = c2049fF.a(i6);
                AbstractC1795We.L(!false);
                sparseBooleanArray2.append(iA, true);
            }
            AbstractC1795We.L(!false);
            sparseBooleanArray2.append(4, true);
            AbstractC1795We.L(!false);
            sparseBooleanArray2.append(10, true);
            AbstractC1795We.L(!false);
            this.G = new C2816x7(new C2049fF(sparseBooleanArray2));
            this.k = this.u.a(this.s, null);
            C2586rt c2586rt = new C2586rt(this, i2);
            this.g1 = c2586rt;
            this.d1 = GD.h(this.c);
            this.r.f(this.g, this.s);
            C1917cE c1917cE = new C1917cE(zc.s);
            C2436oD c2436oD = new C2436oD(this.f, this.h, this.i, this.j, this.c, (InterfaceC2522qD) zc.f.zza(), this.t, this.r, this.E, zc.t, zc.o, this.s, this.u, c2586rt, c1917cE, this.F);
            Looper looper2 = c2436oD.j;
            this.l = c2436oD;
            this.V = 1.0f;
            C2082g4 c2082g4 = C2082g4.B;
            this.H = c2082g4;
            this.c1 = c2082g4;
            this.e1 = -1;
            int i7 = Rg.a;
            this.X = true;
            WD wd = this.r;
            com.amazon.aps.ads.privacy.a aVar = this.m;
            if (wd == null) {
                throw null;
            }
            aVar.b(wd);
            C2050fG c2050fG = this.t;
            Handler handler = new Handler(this.s);
            WD wd2 = this.r;
            c2050fG.getClass();
            wd2.getClass();
            Lr lr = c2050fG.c;
            CopyOnWriteArrayList copyOnWriteArrayList = (CopyOnWriteArrayList) lr.b;
            Iterator it2 = copyOnWriteArrayList.iterator();
            while (it2.hasNext()) {
                C1919cG c1919cG = (C1919cG) it2.next();
                if (c1919cG.b == wd2) {
                    c1919cG.c = true;
                    copyOnWriteArrayList.remove(c1919cG);
                }
            }
            ((CopyOnWriteArrayList) lr.b).add(new C1919cG(handler, wd2));
            this.n.add(this.v);
            if (Build.VERSION.SDK_INT >= 31) {
                this.u.a(looper2, null).b(new com.google.android.gms.cloudmessaging.g(this.f, zc.q, this, c1917cE));
            }
            com.quizlet.data.interactor.progress.c cVar = new com.quizlet.data.interactor.progress.c(looper2, this.s, this.u, new Lr(this, 7));
            this.A = cVar;
            ((Bo) cVar.a).b(new RunnableC2104gj(this, 23));
            C1847ao c1847ao2 = this.u;
            context.getApplicationContext();
            c1847ao2.a(looper2, null);
            new C1549d(z, 10, c1847ao2.a(looper, null));
            C1847ao c1847ao3 = this.u;
            androidx.camera.camera2.internal.compat.workaround.e eVar = new androidx.camera.camera2.internal.compat.workaround.e(9, z);
            context.getApplicationContext();
            c1847ao3.a(looper2, null);
            this.x = eVar;
            C1847ao c1847ao4 = this.u;
            androidx.camera.camera2.internal.compat.workaround.e eVar2 = new androidx.camera.camera2.internal.compat.workaround.e(10, false);
            context.getApplicationContext();
            c1847ao4.a(looper2, null);
            this.y = eVar2;
            int i8 = VD.a;
            C1740Nd c1740Nd = C1740Nd.d;
            this.L = Pn.c;
            Wl wl = this.M;
            Bo bo = c2436oD.h;
            bo.getClass();
            C2367mo c2367moE = Bo.e();
            c2367moE.a = bo.a.obtainMessage(31, 0, 0, wl);
            c2367moE.a();
            u1(1, 3, this.M);
            u1(2, 4, Integer.valueOf(this.K));
            u1(2, 5, 0);
            u1(1, 9, Boolean.valueOf(this.W));
            u1(6, 8, this.w);
            u1(-1, 16, Integer.valueOf(this.Z));
            this.e.c();
        } catch (Throwable th) {
            this.e.c();
            throw th;
        }
    }

    public static long p1(GD gd) {
        C2518q9 c2518q9 = new C2518q9();
        C2303l9 c2303l9 = new C2303l9();
        A9 a9 = gd.a;
        a9.n(gd.b.a, c2303l9);
        long j = gd.c;
        if (j != -9223372036854775807L) {
            return j;
        }
        a9.e(c2303l9.c, c2518q9, 0L).getClass();
        return 0L;
    }

    public static GD r1(GD gd, int i) {
        GD gdF = gd.f(i);
        return (i == 1 || i == 4) ? gdF.a(false) : gdF;
    }

    public final void A1(boolean z) {
        U();
        GD gd = this.d1;
        int i = gd.n;
        int i2 = 0;
        if (i == 1) {
            if (z) {
                i = 1;
            } else {
                i = 1;
                i2 = 1;
            }
        }
        if (gd.l == z && i == i2 && gd.m == 1) {
            return;
        }
        this.B++;
        GD gdD = gd.d(1, i2, z);
        Bo bo = this.l.h;
        int i3 = (i2 << 4) | 1;
        bo.getClass();
        C2367mo c2367moE = Bo.e();
        c2367moE.a = bo.a.obtainMessage(1, z ? 1 : 0, i3);
        c2367moE.a();
        x1(gdD, 0, false, 5, -9223372036854775807L, -1);
    }

    public final void B1(float f) {
        U();
        String str = Yo.a;
        float fMax = Math.max(DefinitionKt.NO_Float_VALUE, Math.min(f, 1.0f));
        if (this.V == fMax) {
            return;
        }
        this.V = fMax;
        this.l.h.a(32, Float.valueOf(fMax)).a();
        C2806wy c2806wy = new C2806wy(28);
        com.amazon.aps.ads.privacy.a aVar = this.m;
        aVar.d(22, c2806wy);
        aVar.c();
    }

    public final boolean C1() {
        U();
        return this.d1.l;
    }

    public final boolean D1() {
        U();
        return this.d1.b.b();
    }

    public final void E1(SD sd) {
        this.r.f.b(sd);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final void G() {
        U();
    }

    public final void U() {
        this.e.a();
        Thread threadCurrentThread = Thread.currentThread();
        Looper looper = this.s;
        if (threadCurrentThread != looper.getThread()) {
            String name = Thread.currentThread().getName();
            String name2 = looper.getThread().getName();
            String str = Yo.a;
            Locale locale = Locale.US;
            String strE = AbstractC0147y.e("Player is accessed on the wrong thread.\nCurrent thread: '", name, "'\nExpected thread: '", name2, "'\nSee https://developer.android.com/guide/topics/media/issues/player-accessed-on-wrong-thread");
            if (this.X) {
                throw new IllegalStateException(strE);
            }
            AbstractC2096gb.M("ExoPlayerImpl", strE, this.Y ? null : new IllegalStateException());
            this.Y = true;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final void X0(int i, long j) {
        U();
        if (i == -1) {
            return;
        }
        AbstractC1795We.B(i >= 0);
        A9 a9 = this.d1.a;
        if (a9.o() || i < a9.c()) {
            WD wd = this.r;
            if (!wd.i) {
                RD rdG = wd.g();
                wd.i = true;
                wd.i(rdG, -1, new TD(5));
            }
            this.B++;
            if (D1()) {
                AbstractC2096gb.J("ExoPlayerImpl", "seekTo ignored because an ad is playing");
                androidx.recyclerview.widget.N n = new androidx.recyclerview.widget.N(this.d1);
                n.e(1);
                C2221jD c2221jD = (C2221jD) this.g1.b;
                c2221jD.getClass();
                c2221jD.k.b(new RunnableC2793wl(17, c2221jD, n));
                return;
            }
            GD gdF = this.d1;
            int i2 = gdF.e;
            if (i2 == 3 || (i2 == 4 && !a9.o())) {
                gdF = this.d1.f(2);
            }
            int iA1 = a1();
            GD gdS1 = s1(gdF, a9, q1(a9, i, j));
            long jT = Yo.t(j);
            C2436oD c2436oD = this.l;
            c2436oD.getClass();
            c2436oD.h.a(3, new C2393nD(a9, i, jT)).a();
            x1(gdS1, 0, true, 1, o1(gdS1), iA1);
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final int a1() {
        U();
        int iM1 = m1(this.d1);
        if (iM1 == -1) {
            return 0;
        }
        return iM1;
    }

    public final void c() {
        U();
        w1(null);
        int i = Rg.a;
        Bu bu = Bu.e;
        long j = this.d1.r;
        AbstractC2330lu.n(bu);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final void f1() {
        U();
    }

    public final int h() {
        U();
        return this.d1.e;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2863yB
    public final A9 h1() {
        U();
        return this.d1.a;
    }

    public final void k1() {
        String str;
        boolean zB;
        int i = 0;
        String hexString = Integer.toHexString(System.identityHashCode(this));
        String str2 = Yo.a;
        HashSet hashSet = E3.a;
        synchronized (E3.class) {
            str = E3.b;
        }
        StringBuilder sbH = AbstractC0147y.h("Release ", hexString, " [AndroidXMedia3/1.6.1] [", str2, "] [");
        sbH.append(str);
        sbH.append("]");
        AbstractC2096gb.F("ExoPlayerImpl", sbH.toString());
        U();
        androidx.camera.camera2.internal.compat.workaround.e eVar = this.x;
        if (eVar.b) {
            eVar.b = false;
        }
        androidx.camera.camera2.internal.compat.workaround.e eVar2 = this.y;
        if (eVar2.b) {
            eVar2.b = false;
        }
        C2436oD c2436oD = this.l;
        if (c2436oD.E || !c2436oD.j.getThread().isAlive()) {
            zB = true;
        } else {
            c2436oD.E = true;
            C1973dj c1973dj = new C1973dj();
            c2436oD.h.a(7, c1973dj).a();
            zB = c1973dj.b(c2436oD.s);
        }
        if (!zB) {
            com.amazon.aps.ads.privacy.a aVar = this.m;
            aVar.d(10, new C2047fD(i));
            aVar.c();
        }
        this.m.e();
        this.k.a.removeCallbacksAndMessages(null);
        C2050fG c2050fG = this.t;
        WD wd = this.r;
        CopyOnWriteArrayList copyOnWriteArrayList = (CopyOnWriteArrayList) c2050fG.c.b;
        Iterator it2 = copyOnWriteArrayList.iterator();
        while (it2.hasNext()) {
            C1919cG c1919cG = (C1919cG) it2.next();
            if (c1919cG.b == wd) {
                c1919cG.c = true;
                copyOnWriteArrayList.remove(c1919cG);
            }
        }
        this.d1.getClass();
        GD gdR1 = r1(this.d1, 1);
        this.d1 = gdR1;
        GD gdB = gdR1.b(gdR1.b);
        this.d1 = gdB;
        gdB.p = gdB.r;
        this.d1.q = 0L;
        Bo bo = wd.h;
        AbstractC1795We.p(bo);
        bo.b(new RunnableC2104gj(wd, 25));
        Surface surface = this.J;
        if (surface != null) {
            surface.release();
            this.J = null;
        }
        int i2 = Rg.a;
    }

    public final void l1(C2143he c2143he) {
        U();
        com.amazon.aps.ads.privacy.a aVar = this.r.f;
        aVar.f();
        CopyOnWriteArraySet copyOnWriteArraySet = (CopyOnWriteArraySet) aVar.f;
        Iterator it2 = copyOnWriteArraySet.iterator();
        while (it2.hasNext()) {
            C2407nl c2407nl = (C2407nl) it2.next();
            if (c2407nl.a.equals(c2143he)) {
                c2407nl.d = true;
                if (c2407nl.c) {
                    c2407nl.c = false;
                    C2049fF c2049fFN = c2407nl.b.N();
                    ((InterfaceC1844al) aVar.e).c(c2407nl.a, c2049fFN);
                }
                copyOnWriteArraySet.remove(c2407nl);
            }
        }
    }

    public final int m1(GD gd) {
        A9 a9 = gd.a;
        return a9.o() ? this.e1 : a9.n(gd.b.a, this.o).c;
    }

    public final long n1(GD gd) {
        C2093gF c2093gF = gd.b;
        if (!c2093gF.b()) {
            return Yo.w(o1(gd));
        }
        Object obj = c2093gF.a;
        C2303l9 c2303l9 = this.o;
        A9 a9 = gd.a;
        a9.n(obj, c2303l9);
        long j = gd.c;
        if (j == -9223372036854775807L) {
            a9.e(m1(gd), (C2518q9) this.a, 0L).getClass();
            return Yo.w(0L);
        }
        return Yo.w(j) + Yo.w(0L);
    }

    public final long o1(GD gd) {
        A9 a9 = gd.a;
        if (a9.o()) {
            return Yo.t(this.f1);
        }
        long j = gd.r;
        C2093gF c2093gF = gd.b;
        if (c2093gF.b()) {
            return j;
        }
        a9.n(c2093gF.a, this.o);
        return j;
    }

    public final Pair q1(A9 a9, int i, long j) {
        if (a9.o()) {
            this.e1 = i;
            if (j == -9223372036854775807L) {
                j = 0;
            }
            this.f1 = j;
            return null;
        }
        if (i == -1 || i >= a9.c()) {
            i = a9.g(false);
            a9.e(i, (C2518q9) this.a, 0L).getClass();
            j = Yo.w(0L);
        }
        return a9.l((C2518q9) this.a, this.o, i, Yo.t(j));
    }

    public final GD s1(GD gd, A9 a9, Pair pair) {
        List list;
        AbstractC1795We.B(a9.o() || pair != null);
        A9 a92 = gd.a;
        long jN1 = n1(gd);
        GD gdG = gd.g(a9);
        if (a9.o()) {
            C2093gF c2093gF = GD.t;
            long jT = Yo.t(this.f1);
            GD gdB = gdG.c(c2093gF, jT, jT, jT, 0L, HF.d, this.c, Bu.e).b(c2093gF);
            gdB.p = gdB.r;
            return gdB;
        }
        C2093gF c2093gF2 = gdG.b;
        Object obj = c2093gF2.a;
        String str = Yo.a;
        boolean zEquals = obj.equals(pair.first);
        C2093gF c2093gF3 = !zEquals ? new C2093gF(-1L, pair.first) : c2093gF2;
        long jLongValue = ((Long) pair.second).longValue();
        long jT2 = Yo.t(jN1);
        if (!a92.o()) {
            a92.n(obj, this.o);
        }
        if (!zEquals || jLongValue < jT2) {
            C2093gF c2093gF4 = c2093gF3;
            AbstractC1795We.L(!c2093gF4.b());
            HF hf = !zEquals ? HF.d : gdG.h;
            YF yf = !zEquals ? this.c : gdG.i;
            if (zEquals) {
                list = gdG.j;
            } else {
                C2244ju c2244ju = AbstractC2330lu.b;
                list = Bu.e;
            }
            GD gdB2 = gdG.c(c2093gF4, jLongValue, jLongValue, jLongValue, 0L, hf, yf, list).b(c2093gF4);
            gdB2.p = jLongValue;
            return gdB2;
        }
        if (jLongValue != jT2) {
            C2093gF c2093gF5 = c2093gF3;
            AbstractC1795We.L(!c2093gF5.b());
            long jMax = Math.max(0L, gdG.q - (jLongValue - jT2));
            long j = gdG.p;
            if (gdG.k.equals(c2093gF2)) {
                j = jLongValue + jMax;
            }
            GD gdC = gdG.c(c2093gF5, jLongValue, jLongValue, jLongValue, jMax, gdG.h, gdG.i, gdG.j);
            gdC.p = j;
            return gdC;
        }
        int iA = a9.a(gdG.k.a);
        if (iA != -1) {
            C2303l9 c2303l9 = this.o;
            if (a9.d(iA, c2303l9, false).c == a9.n(c2093gF3.a, c2303l9).c) {
                return gdG;
            }
        }
        Object obj2 = c2093gF3.a;
        C2303l9 c2303l92 = this.o;
        a9.n(obj2, c2303l92);
        long jA = c2093gF3.b() ? c2303l92.a(c2093gF3.b, c2093gF3.c) : c2303l92.d;
        C2093gF c2093gF6 = c2093gF3;
        GD gdB3 = gdG.c(c2093gF6, gdG.r, gdG.r, gdG.d, jA - gdG.r, gdG.h, gdG.i, gdG.j).b(c2093gF6);
        gdB3.p = jA;
        return gdB3;
    }

    public final void t1(int i, int i2) {
        Pn pn = this.L;
        if (i == pn.a && i2 == pn.b) {
            return;
        }
        this.L = new Pn(i, i2);
        C2806wy c2806wy = new C2806wy(29);
        com.amazon.aps.ads.privacy.a aVar = this.m;
        aVar.d(24, c2806wy);
        aVar.c();
        u1(2, 14, new Pn(i, i2));
    }

    public final void u1(int i, int i2, Object obj) {
        C2436oD c2436oD;
        JE[] jeArr = this.h;
        int length = jeArr.length;
        int i3 = 0;
        while (true) {
            c2436oD = this.l;
            if (i3 >= 2) {
                break;
            }
            JE je = jeArr[i3];
            if (i == -1 || je.b == i) {
                m1(this.d1);
                A9 a9 = this.d1.a;
                JD jd = new JD(c2436oD, je, c2436oD.j);
                AbstractC1795We.L(!jd.f);
                jd.c = i2;
                AbstractC1795We.L(!jd.f);
                jd.d = obj;
                jd.a();
            }
            i3++;
        }
        JE[] jeArr2 = this.i;
        int length2 = jeArr2.length;
        for (int i4 = 0; i4 < 2; i4++) {
            JE je2 = jeArr2[i4];
            if (je2 != null && (i == -1 || je2.b == i)) {
                m1(this.d1);
                A9 a92 = this.d1.a;
                JD jd2 = new JD(c2436oD, je2, c2436oD.j);
                AbstractC1795We.L(!jd2.f);
                jd2.c = i2;
                AbstractC1795We.L(!jd2.f);
                jd2.d = obj;
                jd2.a();
            }
        }
    }

    public final void v1(Surface surface) {
        Surface surface2 = this.I;
        boolean z = false;
        boolean zB = true;
        if (surface2 != null && surface2 != surface) {
            z = true;
        }
        long j = z ? this.z : -9223372036854775807L;
        C2436oD c2436oD = this.l;
        if (!c2436oD.E && c2436oD.j.getThread().isAlive()) {
            C1973dj c1973dj = new C1973dj();
            c2436oD.h.a(30, new Pair(surface, c1973dj)).a();
            if (j != -9223372036854775807L) {
                zB = c1973dj.b(j);
            }
        }
        if (z) {
            Surface surface3 = this.I;
            Surface surface4 = this.J;
            if (surface3 == surface4) {
                surface4.release();
                this.J = null;
            }
        }
        this.I = surface;
        if (zB) {
            return;
        }
        w1(new zzik(2, new zzkp("Detaching surface timed out."), 1003));
    }

    public final void w1(zzik zzikVar) {
        GD gd = this.d1;
        GD gdB = gd.b(gd.b);
        gdB.p = gdB.r;
        gdB.q = 0L;
        GD gdR1 = r1(gdB, 1);
        if (zzikVar != null) {
            gdR1 = gdR1.e(zzikVar);
        }
        GD gd2 = gdR1;
        this.B++;
        Bo bo = this.l.h;
        bo.getClass();
        C2367mo c2367moE = Bo.e();
        c2367moE.a = bo.a.obtainMessage(6);
        c2367moE.a();
        x1(gd2, 0, false, 5, -9223372036854775807L, -1);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:142:0x0233  */
    /* JADX WARN: Removed duplicated region for block: B:143:0x0235  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x023d  */
    /* JADX WARN: Removed duplicated region for block: B:147:0x023f  */
    /* JADX WARN: Removed duplicated region for block: B:150:0x0245  */
    /* JADX WARN: Removed duplicated region for block: B:162:0x0266  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x0277  */
    /* JADX WARN: Removed duplicated region for block: B:169:0x0282  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x028a  */
    /* JADX WARN: Removed duplicated region for block: B:173:0x028c  */
    /* JADX WARN: Removed duplicated region for block: B:175:0x028f  */
    /* JADX WARN: Removed duplicated region for block: B:177:0x029e  */
    /* JADX WARN: Removed duplicated region for block: B:196:0x033f  */
    /* JADX WARN: Removed duplicated region for block: B:197:0x036f  */
    /* JADX WARN: Removed duplicated region for block: B:200:0x0387  */
    /* JADX WARN: Removed duplicated region for block: B:201:0x0394  */
    /* JADX WARN: Removed duplicated region for block: B:203:0x03b6  */
    /* JADX WARN: Removed duplicated region for block: B:205:0x03ba  */
    /* JADX WARN: Removed duplicated region for block: B:208:0x03cc  */
    /* JADX WARN: Removed duplicated region for block: B:213:0x03ea  */
    /* JADX WARN: Removed duplicated region for block: B:215:0x03fe  */
    /* JADX WARN: Removed duplicated region for block: B:217:0x040e  */
    /* JADX WARN: Removed duplicated region for block: B:218:0x041b  */
    /* JADX WARN: Removed duplicated region for block: B:221:0x0420  */
    /* JADX WARN: Removed duplicated region for block: B:224:0x042e  */
    /* JADX WARN: Removed duplicated region for block: B:231:0x0444  */
    /* JADX WARN: Removed duplicated region for block: B:234:0x0457  */
    /* JADX WARN: Removed duplicated region for block: B:237:0x046c  */
    /* JADX WARN: Removed duplicated region for block: B:240:0x0482  */
    /* JADX WARN: Removed duplicated region for block: B:246:0x04b6  */
    /* JADX WARN: Removed duplicated region for block: B:249:0x04c1  */
    /* JADX WARN: Removed duplicated region for block: B:250:0x04c4  */
    /* JADX WARN: Removed duplicated region for block: B:256:0x04e2  */
    /* JADX WARN: Removed duplicated region for block: B:257:0x04e6  */
    /* JADX WARN: Removed duplicated region for block: B:263:0x0506  */
    /* JADX WARN: Removed duplicated region for block: B:267:0x0520  */
    /* JADX WARN: Removed duplicated region for block: B:270:0x052d  */
    /* JADX WARN: Removed duplicated region for block: B:274:0x0544  */
    /* JADX WARN: Removed duplicated region for block: B:278:0x0560 A[LOOP:0: B:276:0x0558->B:278:0x0560, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:281:0x0570  */
    /* JADX WARN: Removed duplicated region for block: B:283:0x0575 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:285:0x057a  */
    /* JADX WARN: Removed duplicated region for block: B:287:0x057d  */
    /* JADX WARN: Removed duplicated region for block: B:289:0x0583 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:291:0x0588  */
    /* JADX WARN: Removed duplicated region for block: B:293:0x058b  */
    /* JADX WARN: Removed duplicated region for block: B:295:0x0590 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:299:0x0597  */
    /* JADX WARN: Removed duplicated region for block: B:303:0x059f  */
    /* JADX WARN: Removed duplicated region for block: B:305:0x05a5 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:307:0x05aa  */
    /* JADX WARN: Removed duplicated region for block: B:309:0x05ad  */
    /* JADX WARN: Removed duplicated region for block: B:311:0x05b4 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:315:0x05bb  */
    /* JADX WARN: Removed duplicated region for block: B:319:0x05c3  */
    /* JADX WARN: Removed duplicated region for block: B:321:0x05ca  */
    /* JADX WARN: Removed duplicated region for block: B:323:0x05d1 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:325:0x05d6  */
    /* JADX WARN: Removed duplicated region for block: B:327:0x05d9  */
    /* JADX WARN: Removed duplicated region for block: B:329:0x05e0 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:331:0x05e5  */
    /* JADX WARN: Removed duplicated region for block: B:333:0x05e8  */
    /* JADX WARN: Removed duplicated region for block: B:336:0x05fc  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00e5  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0111  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0121  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0152  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0156  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void x1(final com.google.android.gms.internal.ads.GD r32, int r33, boolean r34, int r35, long r36, int r38) {
        /*
            Method dump skipped, instructions count: 1552
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2221jD.x1(com.google.android.gms.internal.ads.GD, int, boolean, int, long, int):void");
    }

    public final long y1() {
        U();
        return Yo.w(o1(this.d1));
    }

    public final long z1() {
        U();
        if (!D1()) {
            A9 a9H1 = h1();
            if (a9H1.o()) {
                return -9223372036854775807L;
            }
            return Yo.w(a9H1.e(a1(), (C2518q9) this.a, 0L).j);
        }
        GD gd = this.d1;
        C2093gF c2093gF = gd.b;
        Object obj = c2093gF.a;
        A9 a9 = gd.a;
        C2303l9 c2303l9 = this.o;
        a9.n(obj, c2303l9);
        return Yo.w(c2303l9.a(c2093gF.b, c2093gF.c));
    }
}
