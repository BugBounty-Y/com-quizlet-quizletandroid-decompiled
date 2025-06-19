package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.res.Resources;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/* renamed from: com.google.android.gms.internal.ads.ed, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2010ed {
    public final Object a = new Object();
    public final com.google.android.gms.ads.internal.util.C b;
    public final C2098gd c;
    public boolean d;
    public Context e;
    public VersionInfoParcel f;
    public String g;
    public com.google.android.datatransport.cct.internal.s h;
    public Boolean i;
    public final AtomicInteger j;
    public final AtomicInteger k;
    public final C1967dd l;
    public final Object m;
    public com.google.common.util.concurrent.e n;
    public final AtomicBoolean o;

    public C2010ed() {
        com.google.android.gms.ads.internal.util.C c = new com.google.android.gms.ads.internal.util.C();
        this.b = c;
        this.c = new C2098gd(C1614q.f.c, c);
        this.d = false;
        this.h = null;
        this.i = null;
        this.j = new AtomicInteger(0);
        this.k = new AtomicInteger(0);
        this.l = new C1967dd();
        this.m = new Object();
        this.o = new AtomicBoolean();
    }

    public final boolean a(Context context) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.t8)).booleanValue()) {
            return this.o.get();
        }
        NetworkInfo activeNetworkInfo = ((ConnectivityManager) context.getSystemService("connectivity")).getActiveNetworkInfo();
        return activeNetworkInfo != null && activeNetworkInfo.isConnected();
    }

    public final Resources b() {
        if (this.f.d) {
            return this.e.getResources();
        }
        try {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Sa)).booleanValue()) {
                return com.google.android.gms.ads.internal.util.client.i.b(this.e).a.getResources();
            }
            com.google.android.gms.ads.internal.util.client.i.b(this.e).a.getResources();
            return null;
        } catch (com.google.android.gms.ads.internal.util.client.zzr e) {
            com.google.android.gms.ads.internal.util.client.i.i("Cannot load resource from dynamite apk or local jar", e);
            return null;
        }
    }

    public final com.google.android.datatransport.cct.internal.s c() {
        com.google.android.datatransport.cct.internal.s sVar;
        synchronized (this.a) {
            sVar = this.h;
        }
        return sVar;
    }

    public final com.google.android.gms.ads.internal.util.C d() {
        com.google.android.gms.ads.internal.util.C c;
        synchronized (this.a) {
            c = this.b;
        }
        return c;
    }

    public final com.google.common.util.concurrent.e e() {
        if (this.e != null) {
            if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.X2)).booleanValue()) {
                synchronized (this.m) {
                    try {
                        com.google.common.util.concurrent.e eVar = this.n;
                        if (eVar != null) {
                            return eVar;
                        }
                        com.google.common.util.concurrent.e eVarD = AbstractC2270kd.a.d(new Q4(this, 1));
                        this.n = eVarD;
                        return eVarD;
                    } catch (Throwable th) {
                        throw th;
                    }
                }
            }
        }
        return AbstractC2025es.E(new ArrayList());
    }

    public final void f(Context context, VersionInfoParcel versionInfoParcel) {
        com.google.android.datatransport.cct.internal.s sVar;
        synchronized (this.a) {
            try {
                if (!this.d) {
                    this.e = context.getApplicationContext();
                    this.f = versionInfoParcel;
                    com.google.android.gms.ads.internal.j.C.g.l(this.c);
                    this.b.p(this.e);
                    C1744Ob.b(this.e, this.f);
                    C2601s7 c2601s7 = AbstractC2773w7.a2;
                    com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                    if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                        sVar = new com.google.android.datatransport.cct.internal.s(1);
                    } else {
                        com.google.android.gms.ads.internal.util.A.l("CsiReporterFactory: CSI is not enabled. No CSI reporter created.");
                        sVar = null;
                    }
                    this.h = sVar;
                    if (sVar != null) {
                        AbstractC1972di.f(new com.google.android.gms.ads.internal.overlay.g(this, 2).R(), "AppState.registerCsiReporter");
                    }
                    Context context2 = this.e;
                    if (((Boolean) rVar.c.a(AbstractC2773w7.t8)).booleanValue()) {
                        try {
                            ((ConnectivityManager) context2.getSystemService("connectivity")).registerDefaultNetworkCallback(new androidx.work.impl.constraints.d(this, 4));
                        } catch (RuntimeException e) {
                            com.google.android.gms.ads.internal.util.client.i.i("Failed to register network callback", e);
                            this.o.set(true);
                        }
                    }
                    this.d = true;
                    e();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        com.google.android.gms.ads.internal.j.C.c.y(context, versionInfoParcel.a);
    }

    public final void g(String str, Throwable th) {
        C1744Ob.b(this.e, this.f).e(th, str, ((Double) AbstractC2086g8.f.o()).floatValue());
    }

    public final void h(String str, Throwable th) {
        C1744Ob.b(this.e, this.f).d(str, th);
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0037 A[Catch: all -> 0x0035, TryCatch #0 {all -> 0x0035, blocks: (B:4:0x0007, B:6:0x000b, B:8:0x001d, B:10:0x002d, B:13:0x0037, B:14:0x0040), top: B:19:0x0007 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void i(java.lang.String r7, java.lang.Throwable r8) {
        /*
            r6 = this;
            android.content.Context r0 = r6.e
            com.google.android.gms.ads.internal.util.client.VersionInfoParcel r1 = r6.f
            java.lang.Object r2 = com.google.android.gms.internal.ads.C1744Ob.l
            monitor-enter(r2)
            com.google.android.gms.internal.ads.Pb r3 = com.google.android.gms.internal.ads.C1744Ob.n     // Catch: java.lang.Throwable -> L35
            if (r3 != 0) goto L40
            com.google.android.gms.internal.ads.s7 r3 = com.google.android.gms.internal.ads.AbstractC2773w7.H7     // Catch: java.lang.Throwable -> L35
            com.google.android.gms.ads.internal.client.r r4 = com.google.android.gms.ads.internal.client.r.d     // Catch: java.lang.Throwable -> L35
            com.google.android.gms.internal.ads.u7 r5 = r4.c     // Catch: java.lang.Throwable -> L35
            java.lang.Object r3 = r5.a(r3)     // Catch: java.lang.Throwable -> L35
            java.lang.Boolean r3 = (java.lang.Boolean) r3     // Catch: java.lang.Throwable -> L35
            boolean r3 = r3.booleanValue()     // Catch: java.lang.Throwable -> L35
            if (r3 == 0) goto L37
            com.google.android.gms.internal.ads.s7 r3 = com.google.android.gms.internal.ads.AbstractC2773w7.G7     // Catch: java.lang.Throwable -> L35
            com.google.android.gms.internal.ads.u7 r4 = r4.c     // Catch: java.lang.Throwable -> L35
            java.lang.Object r3 = r4.a(r3)     // Catch: java.lang.Throwable -> L35
            java.lang.Boolean r3 = (java.lang.Boolean) r3     // Catch: java.lang.Throwable -> L35
            boolean r3 = r3.booleanValue()     // Catch: java.lang.Throwable -> L35
            if (r3 != 0) goto L37
            com.google.android.gms.internal.ads.Ob r3 = new com.google.android.gms.internal.ads.Ob     // Catch: java.lang.Throwable -> L35
            r3.<init>(r0, r1)     // Catch: java.lang.Throwable -> L35
            com.google.android.gms.internal.ads.C1744Ob.n = r3     // Catch: java.lang.Throwable -> L35
            goto L40
        L35:
            r7 = move-exception
            goto L47
        L37:
            com.google.android.gms.internal.ads.L9 r0 = new com.google.android.gms.internal.ads.L9     // Catch: java.lang.Throwable -> L35
            r1 = 14
            r0.<init>(r1)     // Catch: java.lang.Throwable -> L35
            com.google.android.gms.internal.ads.C1744Ob.n = r0     // Catch: java.lang.Throwable -> L35
        L40:
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L35
            com.google.android.gms.internal.ads.Pb r0 = com.google.android.gms.internal.ads.C1744Ob.n
            r0.d(r7, r8)
            return
        L47:
            monitor-exit(r2)     // Catch: java.lang.Throwable -> L35
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2010ed.i(java.lang.String, java.lang.Throwable):void");
    }
}
