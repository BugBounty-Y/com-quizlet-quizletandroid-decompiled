package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import android.os.SystemClock;
import com.google.android.gms.ads.internal.client.InterfaceC1609n0;
import com.google.android.gms.ads.internal.client.InterfaceC1619u;
import com.google.android.gms.ads.internal.client.InterfaceC1622x;
import com.google.android.gms.ads.internal.client.zzfw;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.internal.client.zzx;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: com.google.android.gms.internal.ads.sp, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2625sp extends com.google.android.gms.ads.internal.client.J implements com.google.android.gms.ads.internal.overlay.j, T5 {
    public final C1765Re a;
    public final Context b;
    public final String d;
    public final C2454op e;
    public final C2411np f;
    public final VersionInfoParcel g;
    public final Hk h;
    public C1748Of j;
    public C1766Rf k;
    public AtomicBoolean c = new AtomicBoolean();
    public long i = -1;

    public BinderC2625sp(C1765Re c1765Re, Context context, String str, C2454op c2454op, C2411np c2411np, VersionInfoParcel versionInfoParcel, Hk hk) {
        this.a = c1765Re;
        this.b = context;
        this.d = str;
        this.e = c2454op;
        this.f = c2411np;
        this.g = versionInfoParcel;
        this.h = hk;
        c2411np.f.set(this);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A0(com.google.android.gms.ads.internal.client.P p) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void A1(com.google.android.gms.ads.internal.client.zzr zzrVar) {
        com.google.android.gms.common.internal.u.d("setAdSize must be called on the main UI thread.");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A3(InterfaceC1619u interfaceC1619u) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void E1(C2097gc c2097gc) {
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x000f  */
    @Override // com.google.android.gms.ads.internal.client.K
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized boolean F3() {
        /*
            r1 = this;
            monitor-enter(r1)
            com.google.android.gms.internal.ads.op r0 = r1.e     // Catch: java.lang.Throwable -> L12
            com.google.common.util.concurrent.e r0 = r0.j     // Catch: java.lang.Throwable -> L12
            if (r0 == 0) goto Lf
            boolean r0 = r0.isDone()     // Catch: java.lang.Throwable -> L12
            if (r0 != 0) goto Lf
            r0 = 1
            goto L10
        Lf:
            r0 = 0
        L10:
            monitor-exit(r1)
            return r0
        L12:
            r0 = move-exception
            monitor-exit(r1)     // Catch: java.lang.Throwable -> L12
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.BinderC2625sp.F3():boolean");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void H() {
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x002f  */
    @Override // com.google.android.gms.ads.internal.client.K
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized boolean I2(com.google.android.gms.ads.internal.client.zzm r6) {
        /*
            r5 = this;
            monitor-enter(r5)
            java.lang.String r0 = "is_sdk_preload"
            android.os.Bundle r1 = r6.c     // Catch: java.lang.Throwable -> L31
            r2 = 0
            boolean r0 = r1.getBoolean(r0, r2)     // Catch: java.lang.Throwable -> L31
            if (r0 == 0) goto Ld
            goto L50
        Ld:
            com.google.android.gms.internal.ads.I3 r0 = com.google.android.gms.internal.ads.U7.d     // Catch: java.lang.Throwable -> L31
            java.lang.Object r0 = r0.o()     // Catch: java.lang.Throwable -> L31
            java.lang.Boolean r0 = (java.lang.Boolean) r0     // Catch: java.lang.Throwable -> L31
            boolean r0 = r0.booleanValue()     // Catch: java.lang.Throwable -> L31
            if (r0 == 0) goto L2f
            com.google.android.gms.internal.ads.s7 r0 = com.google.android.gms.internal.ads.AbstractC2773w7.hb     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.ads.internal.client.r r1 = com.google.android.gms.ads.internal.client.r.d     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.internal.ads.u7 r1 = r1.c     // Catch: java.lang.Throwable -> L31
            java.lang.Object r0 = r1.a(r0)     // Catch: java.lang.Throwable -> L31
            java.lang.Boolean r0 = (java.lang.Boolean) r0     // Catch: java.lang.Throwable -> L31
            boolean r0 = r0.booleanValue()     // Catch: java.lang.Throwable -> L31
            if (r0 == 0) goto L2f
            r0 = 1
            goto L33
        L2f:
            r0 = r2
            goto L33
        L31:
            r6 = move-exception
            goto L98
        L33:
            com.google.android.gms.ads.internal.util.client.VersionInfoParcel r1 = r5.g     // Catch: java.lang.Throwable -> L31
            int r1 = r1.c     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.internal.ads.s7 r3 = com.google.android.gms.internal.ads.AbstractC2773w7.ib     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.ads.internal.client.r r4 = com.google.android.gms.ads.internal.client.r.d     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.internal.ads.u7 r4 = r4.c     // Catch: java.lang.Throwable -> L31
            java.lang.Object r3 = r4.a(r3)     // Catch: java.lang.Throwable -> L31
            java.lang.Integer r3 = (java.lang.Integer) r3     // Catch: java.lang.Throwable -> L31
            int r3 = r3.intValue()     // Catch: java.lang.Throwable -> L31
            if (r1 < r3) goto L4b
            if (r0 != 0) goto L50
        L4b:
            java.lang.String r0 = "loadAd must be called on the main UI thread."
            com.google.android.gms.common.internal.u.d(r0)     // Catch: java.lang.Throwable -> L31
        L50:
            com.google.android.gms.ads.internal.j r0 = com.google.android.gms.ads.internal.j.C     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.ads.internal.util.F r0 = r0.c     // Catch: java.lang.Throwable -> L31
            android.content.Context r0 = r5.b     // Catch: java.lang.Throwable -> L31
            boolean r0 = com.google.android.gms.ads.internal.util.F.g(r0)     // Catch: java.lang.Throwable -> L31
            if (r0 == 0) goto L73
            com.google.android.gms.ads.internal.client.zzc r0 = r6.s     // Catch: java.lang.Throwable -> L31
            if (r0 == 0) goto L61
            goto L73
        L61:
            java.lang.String r6 = "Failed to load the ad because app ID is missing."
            com.google.android.gms.ads.internal.util.client.i.e(r6)     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.internal.ads.np r6 = r5.f     // Catch: java.lang.Throwable -> L31
            r0 = 4
            r1 = 0
            com.google.android.gms.ads.internal.client.zze r0 = com.google.android.gms.internal.ads.AbstractC1972di.x(r0, r1, r1)     // Catch: java.lang.Throwable -> L31
            r6.m0(r0)     // Catch: java.lang.Throwable -> L31
            monitor-exit(r5)
            return r2
        L73:
            boolean r0 = r5.F3()     // Catch: java.lang.Throwable -> L31
            if (r0 == 0) goto L7b
            monitor-exit(r5)
            return r2
        L7b:
            java.util.concurrent.atomic.AtomicBoolean r0 = new java.util.concurrent.atomic.AtomicBoolean     // Catch: java.lang.Throwable -> L31
            r0.<init>()     // Catch: java.lang.Throwable -> L31
            r5.c = r0     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.internal.ads.qp r0 = new com.google.android.gms.internal.ads.qp     // Catch: java.lang.Throwable -> L31
            r0.<init>()     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.internal.ads.op r1 = r5.e     // Catch: java.lang.Throwable -> L31
            java.lang.String r2 = r5.d     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.internal.ads.S4 r3 = new com.google.android.gms.internal.ads.S4     // Catch: java.lang.Throwable -> L31
            r4 = 24
            r3.<init>(r5, r4)     // Catch: java.lang.Throwable -> L31
            boolean r6 = r1.a(r6, r2, r0, r3)     // Catch: java.lang.Throwable -> L31
            monitor-exit(r5)
            return r6
        L98:
            monitor-exit(r5)     // Catch: java.lang.Throwable -> L31
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.BinderC2625sp.I2(com.google.android.gms.ads.internal.client.zzm):boolean");
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final synchronized void I3() {
        if (this.k != null) {
            com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
            jVar.k.getClass();
            this.i = SystemClock.elapsedRealtime();
            int i = this.k.k;
            if (i > 0) {
                ScheduledExecutorService scheduledExecutorService = (ScheduledExecutorService) this.a.d.zzb();
                com.google.android.gms.common.util.b bVar = jVar.k;
                C1748Of c1748Of = new C1748Of(scheduledExecutorService, bVar);
                this.j = c1748Of;
                RunnableC2497pp runnableC2497pp = new RunnableC2497pp(this, 1);
                synchronized (c1748Of) {
                    c1748Of.f = runnableC2497pp;
                    bVar.getClass();
                    long j = i;
                    c1748Of.d = SystemClock.elapsedRealtime() + j;
                    c1748Of.c = scheduledExecutorService.schedule(runnableC2497pp, j, TimeUnit.MILLISECONDS);
                }
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void J() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void K() {
        com.google.android.gms.common.internal.u.d("resume must be called on the main UI thread.");
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final synchronized void L2() {
        C1766Rf c1766Rf = this.k;
        if (c1766Rf != null) {
            com.google.android.gms.ads.internal.j.C.k.getClass();
            c1766Rf.d(1, SystemClock.elapsedRealtime() - this.i);
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void M0(com.google.android.gms.ads.internal.client.V v) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void N1(InterfaceC1622x interfaceC1622x) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void O1(com.google.android.gms.ads.internal.client.T t) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void P() {
        com.google.android.gms.common.internal.u.d("pause must be called on the main UI thread.");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void W1(zzfw zzfwVar) {
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void X(int i) {
        if (i == 0) {
            throw null;
        }
        int i2 = i - 1;
        if (i2 == 0) {
            e4(2);
            return;
        }
        if (i2 == 1) {
            e4(4);
        } else if (i2 != 2) {
            e4(6);
        } else {
            e4(3);
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void X3(boolean z) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void Y() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void Y0(zzm zzmVar, com.google.android.gms.ads.internal.client.A a) {
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void Y3() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void b0() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void c3(boolean z) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final boolean e0() {
        return false;
    }

    public final synchronized void e4(int i) {
        try {
            if (this.c.compareAndSet(false, true)) {
                this.f.a();
                C1748Of c1748Of = this.j;
                if (c1748Of != null) {
                    com.google.android.gms.ads.internal.j.C.g.o(c1748Of);
                }
                if (this.k != null) {
                    long jElapsedRealtime = -1;
                    if (this.i != -1) {
                        com.google.android.gms.ads.internal.j.C.k.getClass();
                        jElapsedRealtime = SystemClock.elapsedRealtime() - this.i;
                    }
                    this.k.d(i, jElapsedRealtime);
                }
                y();
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void f1() {
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void f3() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void g0() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void g3(InterfaceC1866b6 interfaceC1866b6) {
        this.f.b.set(interfaceC1866b6);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized com.google.android.gms.ads.internal.client.zzr h() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final com.google.android.gms.ads.internal.client.P i() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void i0() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final Bundle j() {
        return new Bundle();
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void j0() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void j3(InterfaceC1609n0 interfaceC1609n0) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized com.google.android.gms.ads.internal.client.v0 k() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void k1(zzx zzxVar) {
        this.e.i.i = zzxVar;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final com.google.android.gms.dynamic.a m() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized com.google.android.gms.ads.internal.client.s0 n() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void p1(D7 d7) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized String s() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void s1(com.google.android.gms.dynamic.a aVar) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized boolean t3() {
        return false;
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void v3() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized String w() {
        return this.d;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void y() {
        com.google.android.gms.common.internal.u.d("destroy must be called on the main UI thread.");
        C1766Rf c1766Rf = this.k;
        if (c1766Rf != null) {
            c1766Rf.b();
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized String z() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final InterfaceC1622x zzi() {
        return null;
    }
}
