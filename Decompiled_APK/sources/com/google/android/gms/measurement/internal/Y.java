package com.google.android.gms.measurement.internal;

import android.app.Application;
import android.content.Context;
import android.os.Bundle;
import com.google.android.gms.internal.measurement.C3063u1;
import com.google.android.gms.internal.measurement.C3068v1;
import com.google.android.gms.internal.measurement.C3078x1;
import com.google.android.gms.internal.measurement.C3083y1;
import com.google.android.gms.internal.measurement.D1;
import com.google.android.gms.internal.measurement.F1;
import com.google.android.gms.internal.measurement.G1;
import com.google.android.gms.internal.measurement.zzdh;
import java.io.Serializable;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes2.dex */
public final class Y implements InterfaceC3873i0 {
    public static volatile Y H;
    public long A;
    public volatile Boolean B;
    public volatile boolean C;
    public int D;
    public int E;
    public final long G;
    public final Context a;
    public final String b;
    public final String c;
    public final String d;
    public final boolean e;
    public final com.google.android.material.shape.e f;
    public final C3864e g;
    public final O h;
    public final I i;
    public final X j;
    public final g1 k;
    public final x1 l;
    public final D m;
    public final com.google.android.gms.common.util.b n;
    public final O0 o;
    public final D0 p;
    public final C3884o q;
    public final H0 r;
    public final String s;
    public C t;
    public Y0 u;
    public C3880m v;
    public A w;
    public I0 x;
    public Boolean z;
    public boolean y = false;
    public final AtomicInteger F = new AtomicInteger(0);

    public Y(C3889q0 c3889q0) {
        Context context;
        Context context2 = c3889q0.a;
        com.google.android.material.shape.e eVar = new com.google.android.material.shape.e(10);
        this.f = eVar;
        AbstractC3883n0.k = eVar;
        this.a = context2;
        this.b = c3889q0.b;
        this.c = c3889q0.c;
        this.d = c3889q0.d;
        this.e = c3889q0.h;
        this.B = c3889q0.e;
        this.s = c3889q0.j;
        this.C = true;
        if (F1.h == null && context2 != null) {
            Object obj = F1.g;
            synchronized (obj) {
                try {
                    if (F1.h == null) {
                        synchronized (obj) {
                            C3063u1 c3063u1 = F1.h;
                            Context applicationContext = context2.getApplicationContext();
                            if (applicationContext == null) {
                                applicationContext = context2;
                            }
                            if (c3063u1 == null || c3063u1.a != applicationContext) {
                                if (c3063u1 != null) {
                                    C3068v1.c();
                                    G1.a();
                                    synchronized (C3083y1.class) {
                                        try {
                                            C3083y1 c3083y1 = C3083y1.e;
                                            if (c3083y1 != null && (context = (Context) c3083y1.c) != null && ((C3078x1) c3083y1.d) != null && c3083y1.b) {
                                                context.getContentResolver().unregisterContentObserver((C3078x1) C3083y1.e.d);
                                            }
                                            C3083y1.e = null;
                                        } finally {
                                        }
                                    }
                                }
                                D1 d1 = new D1(applicationContext);
                                F1.h = new C3063u1(applicationContext, d1 instanceof Serializable ? new com.google.common.base.m(d1) : new com.google.common.base.n(d1));
                                F1.i.incrementAndGet();
                            }
                        }
                    }
                } catch (Throwable th) {
                    throw th;
                } finally {
                }
            }
        }
        this.n = com.google.android.gms.common.util.b.a;
        Long l = c3889q0.i;
        this.G = l != null ? l.longValue() : System.currentTimeMillis();
        C3864e c3864e = new C3864e(this);
        c3864e.e = new com.google.firebase.heartbeatinfo.e(10);
        this.g = c3864e;
        O o = new O(this);
        o.V();
        this.h = o;
        I i = new I(this);
        i.V();
        this.i = i;
        x1 x1Var = new x1(this);
        x1Var.V();
        this.l = x1Var;
        this.m = new D(new androidx.appcompat.app.L(this, 23));
        this.q = new C3884o(this);
        O0 o0 = new O0(this);
        o0.T();
        this.o = o0;
        D0 d0 = new D0(this);
        d0.T();
        this.p = d0;
        g1 g1Var = new g1(this);
        g1Var.T();
        this.k = g1Var;
        H0 h0 = new H0(this);
        h0.V();
        this.r = h0;
        X x = new X(this);
        x.V();
        this.j = x;
        zzdh zzdhVar = c3889q0.g;
        boolean z = zzdhVar == null || zzdhVar.b == 0;
        if (context2.getApplicationContext() instanceof Application) {
            j(d0);
            if (((Y) d0.b).a.getApplicationContext() instanceof Application) {
                Application application = (Application) ((Y) d0.b).a.getApplicationContext();
                if (d0.d == null) {
                    d0.d = new C0(d0);
                }
                if (z) {
                    application.unregisterActivityLifecycleCallbacks(d0.d);
                    application.registerActivityLifecycleCallbacks(d0.d);
                    I i2 = ((Y) d0.b).i;
                    k(i2);
                    i2.o.f("Registered activity lifecycle callback");
                }
            }
        } else {
            k(i);
            i.j.f("Application context is not an Application");
        }
        x.c0(new com.google.common.util.concurrent.d(this, false, c3889q0, 25));
    }

    public static final void g(AbstractC3886p abstractC3886p) {
        if (abstractC3886p == null) {
            throw new IllegalStateException("Component not created");
        }
    }

    public static final void h(androidx.compose.animation.core.J0 j0) {
        if (j0 == null) {
            throw new IllegalStateException("Component not created");
        }
    }

    public static final void j(AbstractC3888q abstractC3888q) {
        if (abstractC3888q == null) {
            throw new IllegalStateException("Component not created");
        }
        if (!abstractC3888q.c) {
            throw new IllegalStateException("Component not initialized: ".concat(String.valueOf(abstractC3888q.getClass())));
        }
    }

    public static final void k(AbstractC3871h0 abstractC3871h0) {
        if (abstractC3871h0 == null) {
            throw new IllegalStateException("Component not created");
        }
        if (!abstractC3871h0.c) {
            throw new IllegalStateException("Component not initialized: ".concat(String.valueOf(abstractC3871h0.getClass())));
        }
    }

    public static Y q(Context context, zzdh zzdhVar, Long l) {
        Bundle bundle;
        if (zzdhVar != null && (zzdhVar.e == null || zzdhVar.f == null)) {
            zzdhVar = new zzdh(zzdhVar.a, zzdhVar.b, zzdhVar.c, zzdhVar.d, null, null, zzdhVar.g, null);
        }
        com.google.android.gms.common.internal.u.h(context);
        com.google.android.gms.common.internal.u.h(context.getApplicationContext());
        if (H == null) {
            synchronized (Y.class) {
                try {
                    if (H == null) {
                        H = new Y(new C3889q0(context, zzdhVar, l));
                    }
                } finally {
                }
            }
        } else if (zzdhVar != null && (bundle = zzdhVar.g) != null && bundle.containsKey("dataCollectionDefaultEnabled")) {
            com.google.android.gms.common.internal.u.h(H);
            H.B = Boolean.valueOf(bundle.getBoolean("dataCollectionDefaultEnabled"));
        }
        com.google.android.gms.common.internal.u.h(H);
        return H;
    }

    public final boolean a() {
        return l() == 0;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3873i0
    public final com.google.android.material.shape.e b() {
        return this.f;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3873i0
    public final I c() {
        I i = this.i;
        k(i);
        return i;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3873i0
    public final Context d() {
        return this.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0034  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0076  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x007f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean e() {
        /*
            r6 = this;
            boolean r0 = r6.y
            if (r0 == 0) goto Lbb
            com.google.android.gms.measurement.internal.X r0 = r6.j
            k(r0)
            r0.S()
            java.lang.Boolean r0 = r6.z
            com.google.android.gms.common.util.b r1 = r6.n
            if (r0 == 0) goto L34
            long r2 = r6.A
            r4 = 0
            int r2 = (r2 > r4 ? 1 : (r2 == r4 ? 0 : -1))
            if (r2 == 0) goto L34
            boolean r0 = r0.booleanValue()
            if (r0 != 0) goto Lb4
            r1.getClass()
            long r2 = android.os.SystemClock.elapsedRealtime()
            long r4 = r6.A
            long r2 = r2 - r4
            long r2 = java.lang.Math.abs(r2)
            r4 = 1000(0x3e8, double:4.94E-321)
            int r0 = (r2 > r4 ? 1 : (r2 == r4 ? 0 : -1))
            if (r0 <= 0) goto Lb4
        L34:
            r1.getClass()
            long r0 = android.os.SystemClock.elapsedRealtime()
            r6.A = r0
            com.google.android.gms.measurement.internal.x1 r0 = r6.l
            h(r0)
            java.lang.String r1 = "android.permission.INTERNET"
            boolean r1 = r0.G0(r1)
            com.google.android.gms.measurement.internal.e r2 = r6.g
            r3 = 1
            r4 = 0
            if (r1 == 0) goto L76
            java.lang.String r1 = "android.permission.ACCESS_NETWORK_STATE"
            boolean r1 = r0.G0(r1)
            if (r1 == 0) goto L76
            android.content.Context r1 = r6.a
            com.google.android.gms.common.wrappers.b r5 = com.google.android.gms.common.wrappers.c.a(r1)
            boolean r5 = r5.d()
            if (r5 != 0) goto L74
            boolean r5 = r2.V()
            if (r5 != 0) goto L74
            boolean r5 = com.google.android.gms.measurement.internal.x1.N0(r1)
            if (r5 == 0) goto L76
            boolean r1 = com.google.android.gms.measurement.internal.x1.O0(r1)
            if (r1 == 0) goto L76
        L74:
            r1 = r3
            goto L77
        L76:
            r1 = r4
        L77:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r1)
            r6.z = r5
            if (r1 == 0) goto Lb4
            com.google.android.gms.measurement.internal.A r1 = r6.n()
            java.lang.String r1 = r1.Y()
            com.google.android.gms.measurement.internal.A r5 = r6.n()
            java.lang.String r5 = r5.W()
            boolean r0 = r0.A0(r1, r5)
            if (r0 != 0) goto Lae
            r0 = 0
            com.google.android.gms.measurement.internal.s r1 = com.google.android.gms.measurement.internal.AbstractC3893t.p1
            boolean r0 = r2.f0(r0, r1)
            if (r0 != 0) goto Lad
            com.google.android.gms.measurement.internal.A r0 = r6.n()
            java.lang.String r0 = r0.W()
            boolean r0 = android.text.TextUtils.isEmpty(r0)
            if (r0 != 0) goto Lad
            goto Lae
        Lad:
            r3 = r4
        Lae:
            java.lang.Boolean r0 = java.lang.Boolean.valueOf(r3)
            r6.z = r0
        Lb4:
            java.lang.Boolean r0 = r6.z
            boolean r0 = r0.booleanValue()
            return r0
        Lbb:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "AppMeasurement is not initialized"
            r0.<init>(r1)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.Y.e():boolean");
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3873i0
    public final com.google.android.gms.common.util.a f() {
        return this.n;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3873i0
    public final X i() {
        X x = this.j;
        k(x);
        return x;
    }

    public final int l() {
        X x = this.j;
        k(x);
        x.S();
        C3864e c3864e = this.g;
        if (c3864e.T()) {
            return 1;
        }
        k(x);
        x.S();
        if (!this.C) {
            return 8;
        }
        O o = this.h;
        h(o);
        o.S();
        Boolean boolValueOf = o.X().contains("measurement_enabled") ? Boolean.valueOf(o.X().getBoolean("measurement_enabled", true)) : null;
        if (boolValueOf != null) {
            return boolValueOf.booleanValue() ? 0 : 3;
        }
        com.google.android.material.shape.e eVar = ((Y) c3864e.b).f;
        Boolean boolD0 = c3864e.d0("firebase_analytics_collection_enabled");
        return boolD0 != null ? boolD0.booleanValue() ? 0 : 4 : (this.B == null || this.B.booleanValue()) ? 0 : 7;
    }

    public final C3880m m() {
        k(this.v);
        return this.v;
    }

    public final A n() {
        j(this.w);
        return this.w;
    }

    public final C o() {
        j(this.t);
        return this.t;
    }

    public final D p() {
        return this.m;
    }

    public final Y0 r() {
        j(this.u);
        return this.u;
    }

    public final String s() {
        if (this.g.f0(null, AbstractC3893t.p1)) {
            return null;
        }
        return this.b;
    }
}
