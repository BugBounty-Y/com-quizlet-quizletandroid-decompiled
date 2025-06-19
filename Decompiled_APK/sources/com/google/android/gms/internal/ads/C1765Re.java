package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.zzex;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: com.google.android.gms.internal.ads.Re, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1765Re {
    public static C1765Re L0;
    public final DC A;
    public final BC A0;
    public final BC B;
    public final H5 B0;
    public final BC C;
    public final BC C0;
    public final C1969df D;
    public final C1730Lf D0;
    public final BC E;
    public final BC E0;
    public final BC F;
    public final BC F0;
    public final BC G;
    public final BC G0;
    public final BC H;
    public final BC H0;
    public final BC I;
    public final BC I0;
    public final BC J;
    public final BC J0;
    public final BC K;
    public final BC K0;
    public final BC L;
    public final BC M;
    public final BC N;
    public final BC O;
    public final C1729Le P;
    public final BC Q;
    public final C1729Le R;
    public final BC S;
    public final BC T;
    public final BC U;
    public final BC V;
    public final K7 W;
    public final BC X;
    public final BC Y;
    public final C1735Me Z;
    public final C1723Ke a;
    public final BC a0;
    public final C1765Re b = this;
    public final Lo b0;
    public final BC c;
    public final BC c0;
    public final BC d;
    public final C1735Me d0;
    public final BC e;
    public final BC e0;
    public final BC f;
    public final BC f0;
    public final C1741Ne g;
    public final BC g0;
    public final BC h;
    public final BC h0;
    public final BC i;
    public final Ok i0;
    public final C1741Ne j;
    public final BC j0;
    public final BC k;
    public final C1735Me k0;
    public final BC l;
    public final BC l0;
    public final BC m;
    public final Ni m0;
    public final BC n;
    public final BC n0;
    public final BC o;
    public final BC o0;
    public final BC p;
    public final C1747Oe p0;
    public final BC q;
    public final BC q0;
    public final BC r;
    public final BC r0;
    public final BC s;
    public final BC s0;
    public final BC t;
    public final BC t0;
    public final C1735Me u;
    public final C1735Me u0;
    public final BC v;
    public final BC v0;
    public final BC w;
    public final BC w0;
    public final BC x;
    public final BC x0;
    public final BC y;
    public final C1753Pe y0;
    public final BC z;
    public final C1747Oe z0;

    public C1765Re(C1723Ke c1723Ke, L9 l9) {
        this.a = c1723Ke;
        BC bcB = BC.b(AbstractC1795We.v);
        this.c = bcB;
        BC bcB2 = BC.b(new Ok(BC.b(AbstractC1795We.w), 26));
        this.d = bcB2;
        this.e = BC.b(AbstractC1972di.L);
        BC bcB3 = BC.b(new C2240jq(2));
        this.f = bcB3;
        C1741Ne c1741Ne = new C1741Ne(c1723Ke, 0);
        this.g = c1741Ne;
        C1735Me c1735Me = new C1735Me(c1741Ne, 5);
        BC bcB4 = BC.b(AbstractC1972di.D);
        this.h = bcB4;
        BC bcB5 = BC.b(new C1691Fc(c1735Me, bcB4, 18));
        this.i = bcB5;
        C1741Ne c1741Ne2 = new C1741Ne(c1723Ke, 5);
        this.j = c1741Ne2;
        BC bcB6 = BC.b(new C1729Le(bcB5, 4));
        this.k = bcB6;
        BC bcB7 = BC.b(new C2016ej(20));
        this.l = bcB7;
        C1741Ne c1741Ne3 = new C1741Ne(c1723Ke, 1);
        BC bcB8 = BC.b(new H5(3));
        this.m = bcB8;
        HC hcA = JC.a(new C1729Le(BC.b(new C1741Ne(c1723Ke, 4)), 7));
        BC bcB9 = BC.b(new C1703Hc(hcA, new com.google.android.gms.ads.nonagon.signalgeneration.w(c1741Ne, c1741Ne2, 1), c1741Ne, 14));
        this.n = bcB9;
        BC bcB10 = BC.b(new C1730Lf(bcB8, bcB9, 17));
        BC bcB11 = BC.b(LA.r);
        this.o = bcB11;
        BC bcB12 = BC.b(new C1729Le(bcB11, 2));
        int i = IC.c;
        List list = Collections.EMPTY_LIST;
        ArrayList arrayList = new ArrayList(1);
        arrayList.add(bcB12);
        Wg wg = new Wg(new IC(list, arrayList), 17);
        BC bcB13 = BC.b(new Fg(c1741Ne, c1741Ne2, bcB4, 2));
        this.p = bcB13;
        BC bcB14 = BC.b(new com.google.android.gms.ads.nonagon.signalgeneration.n(bcB, c1741Ne, c1741Ne3, bcB5, bcB2, bcB10, c1741Ne2, wg, bcB13));
        this.q = bcB14;
        int i2 = 8;
        BC bcB15 = BC.b(new H5(i2));
        this.r = bcB15;
        BC bcB16 = BC.b(new C2016ej(i2));
        this.s = bcB16;
        BC bcB17 = BC.b(new C1691Fc(c1741Ne, c1741Ne2, 21));
        BC bcB18 = BC.b(new C1735Me(c1741Ne, 8));
        BC bcB19 = BC.b(new C1735Me(c1741Ne, 7));
        BC bcB20 = BC.b(new C1730Lf(bcB14, bcB4, 18));
        BC bcB21 = BC.b(new C1703Hc(c1741Ne, c1741Ne3, bcB17, 15));
        this.t = bcB21;
        C1735Me c1735Me2 = new C1735Me(c1741Ne, 1);
        this.u = c1735Me2;
        BC bcB22 = BC.b(new C2233jj(bcB17, bcB18, bcB19, c1741Ne, c1741Ne2, bcB20, bcB21, c1735Me2, 2));
        this.v = bcB22;
        C1741Ne c1741Ne4 = new C1741Ne(c1723Ke, 2);
        BC bcB23 = BC.b(new Fg(c1741Ne, bcB13, c1741Ne2));
        this.w = bcB23;
        BC bcB24 = BC.b(new C2833xi(bcB9, 25));
        this.x = bcB24;
        this.y = BC.b(new Cif(c1741Ne, c1741Ne2, bcB5, bcB6, bcB7, bcB14, bcB15, bcB16, bcB22, c1741Ne4, bcB13, c1735Me, bcB23, bcB24));
        this.z = BC.b(new C2885yr(BC.b(new C1760Qf(BC.b(new C1760Qf(c1741Ne, (CC) c1741Ne2, bcB2, bcB3, 20)), new C1747Oe(bcB24, c1741Ne, 9), c1741Ne, bcB3)), 0));
        DC dcA = DC.a(this);
        this.A = dcA;
        BC bcB25 = BC.b(new C1741Ne(c1723Ke, 3));
        this.B = bcB25;
        BC bcB26 = BC.b(new C1729Le(bcB25, 1));
        this.C = bcB26;
        C1969df c1969df = new C1969df(l9, 0);
        this.D = c1969df;
        BC bcB27 = BC.b(new C1735Me(c1741Ne, 13));
        this.E = bcB27;
        BC bcB28 = BC.b(LA.v);
        BC bcB29 = BC.b(new Ok(bcB27, 29));
        this.F = bcB29;
        BC bcB30 = BC.b(new com.google.android.gms.ads.nonagon.signalgeneration.t((Object) c1741Ne, bcB28, hcA, bcB29, bcB13, 19));
        this.G = bcB30;
        BC bcB31 = BC.b(new C1760Qf(c1741Ne, bcB27, hcA, bcB24));
        this.H = bcB31;
        BC bcB32 = BC.b(new Ok(bcB26, 24));
        this.I = bcB32;
        BC bcB33 = BC.b(new C1729Le(BC.b(new com.google.android.gms.ads.nonagon.signalgeneration.n(c1741Ne, bcB, bcB26, c1741Ne2, c1969df, bcB27, bcB30, bcB24, bcB31, bcB32)), 5));
        this.J = bcB33;
        BC bcB34 = BC.b(new com.google.android.gms.ads.nonagon.signalgeneration.w(c1741Ne, bcB9, 2));
        BC bcB35 = BC.b(new com.google.android.gms.ads.nonagon.signalgeneration.w(c1741Ne, c1741Ne2, 0));
        this.K = BC.b(new com.google.android.gms.ads.nonagon.signalgeneration.j(dcA, c1741Ne, bcB26, bcB33, bcB2, bcB9, bcB30, c1741Ne2, new com.google.android.gms.ads.nonagon.signalgeneration.H(bcB2, bcB34, bcB35, bcB9, 1), bcB32, bcB34, bcB35));
        this.L = BC.b(new com.google.android.gms.ads.nonagon.signalgeneration.p(bcB9, 1));
        this.M = BC.b(AbstractC2096gb.t);
        this.N = BC.b(new com.google.android.gms.ads.internal.util.x(c1741Ne, 0));
        BC bcB36 = BC.b(new H5(1));
        this.O = bcB36;
        this.P = new C1729Le(bcB36, 6);
        this.Q = BC.b(new C2833xi(bcB3, 26));
        int i3 = 0;
        this.R = new C1729Le(bcB36, 0);
        BC bcB37 = BC.b(new C1735Me(c1741Ne, i3));
        this.S = bcB37;
        BC bcB38 = BC.b(new C1747Oe(c1741Ne, bcB37, i3));
        this.T = bcB38;
        this.U = BC.b(new C1703Hc(new C1735Me(c1741Ne, 25), bcB3, bcB24, 21));
        this.V = BC.b(AbstractC2096gb.s);
        K7 k7 = new K7(bcB37, bcB38, c1741Ne);
        this.W = k7;
        this.X = BC.b(new Co(k7, bcB3, bcB24, 0));
        this.Y = BC.b(AbstractC1795We.t);
        C1735Me c1735Me3 = new C1735Me(c1741Ne, 18);
        this.Z = c1735Me3;
        this.a0 = BC.b(new C1703Hc(c1735Me3, bcB3, bcB24, 24));
        Lo lo = new Lo(c1741Ne, c1741Ne2, c1735Me2);
        this.b0 = lo;
        int i4 = 26;
        this.c0 = BC.b(new C1703Hc(lo, bcB3, bcB24, i4));
        C1735Me c1735Me4 = new C1735Me(c1741Ne, i4);
        this.d0 = c1735Me4;
        this.e0 = BC.b(new C1703Hc(c1735Me4, bcB3, bcB24, 27));
        int i5 = 19;
        this.f0 = BC.b(new C1703Hc(new C1735Me(c1741Ne, i5), bcB3, bcB24, i5));
        int i6 = 22;
        this.g0 = BC.b(new C1730Lf(bcB3, bcB24, i6));
        this.h0 = BC.b(new C1730Lf(bcB3, bcB24, 23));
        Ok ok = new Ok(bcB36, 17);
        this.i0 = ok;
        this.j0 = BC.b(new C1703Hc(ok, bcB3, bcB24, i6));
        C1735Me c1735Me5 = new C1735Me(c1741Ne, 16);
        this.k0 = c1735Me5;
        this.l0 = BC.b(new Ao(c1735Me5, bcB3, bcB24, 0));
        Ni ni = new Ni(c1741Ne2, 1);
        this.m0 = ni;
        this.n0 = BC.b(new C1703Hc(ni, bcB3, bcB24, 23));
        BC bcB39 = BC.b(new H5(2));
        this.o0 = bcB39;
        C1747Oe c1747Oe = new C1747Oe(c1741Ne, bcB39, 5);
        this.p0 = c1747Oe;
        this.q0 = BC.b(new C1703Hc(c1747Oe, bcB3, bcB24, 25));
        this.r0 = BC.b(LA.m);
        BC bcB40 = BC.b(new C1741Ne(c1723Ke, 6));
        this.s0 = bcB40;
        this.t0 = BC.b(new C1703Hc(new C1735Me(c1741Ne, 24), bcB3, bcB24, 20));
        this.u0 = new C1735Me(c1741Ne, 2);
        this.v0 = BC.b(AbstractC1795We.u);
        this.w0 = BC.b(AbstractC2096gb.v);
        this.x0 = BC.b(new C1729Le(bcB5, 3));
        this.y0 = new C1753Pe(dcA, 0);
        int i7 = 1;
        this.z0 = new C1747Oe(c1741Ne, bcB13, i7);
        this.A0 = BC.b(AbstractC1795We.l);
        this.B0 = new H5(6);
        this.C0 = BC.b(new Fg(c1741Ne, c1741Ne2, bcB13, i7));
        this.D0 = new C1730Lf(bcB2, bcB3, 5);
        this.E0 = BC.b(LA.u);
        this.F0 = BC.b(AbstractC2096gb.u);
        this.G0 = BC.b(new C1735Me(c1741Ne, 3));
        this.H0 = BC.b(new C2833xi(bcB24, 11));
        this.I0 = BC.b(AbstractC2096gb.j);
        this.J0 = BC.b(new com.google.android.gms.ads.nonagon.signalgeneration.t(c1741Ne, bcB40, (HC) bcB38, (HC) BC.b(new com.google.android.gms.ads.internal.util.x(c1741Ne, 1)), (HC) bcB2, 0));
        this.K0 = BC.b(new C1735Me(c1741Ne, 28));
    }

    public static C1765Re b(Context context, InterfaceC2825xa interfaceC2825xa, int i) {
        C2227jd c2227jd;
        SharedPreferences sharedPreferences;
        synchronized (C1765Re.class) {
            try {
                C1765Re c1765Re = L0;
                if (c1765Re != null) {
                    return c1765Re;
                }
                com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
                jVar.k.getClass();
                long jCurrentTimeMillis = System.currentTimeMillis();
                AbstractC2773w7.a(context);
                if (((Boolean) Q7.e.o()).booleanValue() && (sharedPreferences = context.getSharedPreferences("admob", 0)) != null) {
                    sharedPreferences.edit().putInt("init_without_write", AbstractC1795We.I(context, "init_without_write") + 1).commit();
                }
                C2326lq c2326lqS = C2326lq.s(context);
                boolean zE = com.google.android.gms.ads.internal.util.F.e((Context) c2326lqS.b);
                VersionInfoParcel versionInfoParcel = new VersionInfoParcel(ModuleDescriptor.MODULE_VERSION, i, true, zE);
                if (((Boolean) X7.c.o()).booleanValue()) {
                    com.google.android.gms.ads.internal.client.Y y = (com.google.android.gms.ads.internal.client.Y) c2326lqS.c;
                    zzex liteSdkVersion = null;
                    if (y != null) {
                        try {
                            liteSdkVersion = y.getLiteSdkVersion();
                        } catch (RemoteException unused) {
                        }
                    }
                    if (liteSdkVersion != null) {
                        versionInfoParcel = new VersionInfoParcel(ModuleDescriptor.MODULE_VERSION, liteSdkVersion.b, true, zE);
                    }
                }
                c2326lqS.z(interfaceC2825xa);
                C1723Ke c1723Ke = new C1723Ke();
                c1723Ke.a = versionInfoParcel;
                c1723Ke.d = new WeakReference(context);
                c1723Ke.b = context.getApplicationContext() != null ? context.getApplicationContext() : context;
                c1723Ke.c = jCurrentTimeMillis;
                C1723Ke c1723Ke2 = new C1723Ke();
                c1723Ke2.a = c1723Ke.a;
                c1723Ke2.b = c1723Ke.b;
                c1723Ke2.d = c1723Ke.d;
                c1723Ke2.c = c1723Ke.c;
                C1765Re c1765Re2 = new C1765Re(c1723Ke2, new L9(27));
                C2601s7 c2601s7 = AbstractC2773w7.sd;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                    C2142hd c2142hd = jVar.e;
                    C2227jd c2227jd2 = AbstractC2270kd.a;
                    AbstractC1981ds.s(c2227jd2);
                    c2142hd.b(c2227jd2, (Hk) c1765Re2.x.zzb());
                    C2142hd c2142hd2 = jVar.e;
                    if (((AtomicBoolean) c2142hd2.f).get() && c2142hd2.b >= 0 && c2142hd2.c >= 0 && ((AtomicBoolean) c2142hd2.g).compareAndSet(false, true) && (c2227jd = (C2227jd) c2142hd2.d) != null) {
                        c2227jd.a(new RunnableC1989e(c2142hd2, 15));
                    }
                }
                jVar.h.f(context, versionInfoParcel);
                jVar.j.s(context);
                jVar.c.C(context);
                jVar.c.B(context);
                com.google.android.gms.internal.mlkit_vision_common.Y2.d(context);
                jVar.g.n(context);
                jVar.z.f(context);
                ((com.google.android.gms.ads.internal.util.w) c1765Re2.N.zzb()).a();
                C1721Kc.i(context);
                if (((Boolean) rVar.c.a(AbstractC2773w7.g6)).booleanValue()) {
                    if (!((Boolean) rVar.c.a(AbstractC2773w7.D0)).booleanValue()) {
                        C2429o6 c2429o6 = new C2429o6(new C2472p6(context));
                        Fi fi = new Fi(22, new Zl(context), (Xv) c1765Re2.e.zzb());
                        try {
                            fi.h(new androidx.appcompat.app.K(new C2326lq(context, versionInfoParcel, c2429o6, fi), jVar.h.d().k()));
                        } catch (Exception e) {
                            com.google.android.gms.ads.internal.util.client.i.e("Error in offline signals database startup: ".concat(String.valueOf(e.getMessage())));
                        }
                    }
                }
                L0 = c1765Re2;
                return c1765Re2;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final Executor a() {
        return (Executor) this.c.zzb();
    }

    public final Uq c() {
        return (Uq) this.p.zzb();
    }
}
