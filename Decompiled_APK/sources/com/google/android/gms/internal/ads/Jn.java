package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import android.os.RemoteException;
import android.widget.FrameLayout;
import com.google.android.gms.ads.internal.client.InterfaceC1609n0;
import com.google.android.gms.ads.internal.client.InterfaceC1619u;
import com.google.android.gms.ads.internal.client.InterfaceC1622x;
import com.google.android.gms.ads.internal.client.zzfw;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.internal.client.zzx;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.Collections;

/* loaded from: classes2.dex */
public final class Jn extends com.google.android.gms.ads.internal.client.J implements Eh {
    public final Context a;
    public final C2668tp b;
    public final String c;
    public final Ln d;
    public com.google.android.gms.ads.internal.client.zzr e;
    public final C1979dq f;
    public final VersionInfoParcel g;
    public final Hk h;
    public C1778Tf i;

    public Jn(Context context, com.google.android.gms.ads.internal.client.zzr zzrVar, String str, C2668tp c2668tp, Ln ln, VersionInfoParcel versionInfoParcel, Hk hk) {
        this.a = context;
        this.b = c2668tp;
        this.e = zzrVar;
        this.c = str;
        this.d = ln;
        this.f = c2668tp.k;
        this.g = versionInfoParcel;
        this.h = hk;
        c2668tp.h.i1(this, c2668tp.b);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A0(com.google.android.gms.ads.internal.client.P p) {
        if (f4()) {
            com.google.android.gms.common.internal.u.d("setAppEventListener must be called on the main UI thread.");
        }
        this.d.o(p);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void A1(com.google.android.gms.ads.internal.client.zzr zzrVar) {
        InterfaceC2529qe interfaceC2529qe;
        com.google.android.gms.common.internal.u.d("setAdSize must be called on the main UI thread.");
        this.f.b = zzrVar;
        this.e = zzrVar;
        C1778Tf c1778Tf = this.i;
        if (c1778Tf != null) {
            FrameLayout frameLayout = this.b.f;
            if (frameLayout != null && (interfaceC2529qe = c1778Tf.l) != null) {
                interfaceC2529qe.k0(com.bumptech.glide.load.engine.cache.f.a(zzrVar));
                frameLayout.setMinimumHeight(zzrVar.c);
                frameLayout.setMinimumWidth(zzrVar.f);
                c1778Tf.s = zzrVar;
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A3(InterfaceC1619u interfaceC1619u) {
        if (f4()) {
            com.google.android.gms.common.internal.u.d("setAdListener must be called on the main UI thread.");
        }
        Nn nn = this.b.e;
        synchronized (nn) {
            nn.a = interfaceC1619u;
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void E1(C2097gc c2097gc) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized boolean F3() {
        return this.b.a();
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void H() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized boolean I2(zzm zzmVar) {
        com.google.android.gms.ads.internal.client.zzr zzrVar = this.e;
        synchronized (this) {
            C1979dq c1979dq = this.f;
            c1979dq.b = zzrVar;
            c1979dq.q = this.e.n;
        }
        return e4(zzmVar);
        return e4(zzmVar);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void J() {
        com.google.android.gms.common.internal.u.d("setAdMetadataListener must be called on the main UI thread.");
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0038 A[Catch: all -> 0x0036, TryCatch #0 {all -> 0x0036, blocks: (B:3:0x0001, B:5:0x000f, B:7:0x0021, B:13:0x003d, B:15:0x0041, B:12:0x0038), top: B:22:0x0001 }] */
    @Override // com.google.android.gms.ads.internal.client.K
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized void K() {
        /*
            r3 = this;
            monitor-enter(r3)
            com.google.android.gms.internal.ads.I3 r0 = com.google.android.gms.internal.ads.U7.h     // Catch: java.lang.Throwable -> L36
            java.lang.Object r0 = r0.o()     // Catch: java.lang.Throwable -> L36
            java.lang.Boolean r0 = (java.lang.Boolean) r0     // Catch: java.lang.Throwable -> L36
            boolean r0 = r0.booleanValue()     // Catch: java.lang.Throwable -> L36
            if (r0 == 0) goto L38
            com.google.android.gms.internal.ads.s7 r0 = com.google.android.gms.internal.ads.AbstractC2773w7.db     // Catch: java.lang.Throwable -> L36
            com.google.android.gms.ads.internal.client.r r1 = com.google.android.gms.ads.internal.client.r.d     // Catch: java.lang.Throwable -> L36
            com.google.android.gms.internal.ads.u7 r2 = r1.c     // Catch: java.lang.Throwable -> L36
            java.lang.Object r0 = r2.a(r0)     // Catch: java.lang.Throwable -> L36
            java.lang.Boolean r0 = (java.lang.Boolean) r0     // Catch: java.lang.Throwable -> L36
            boolean r0 = r0.booleanValue()     // Catch: java.lang.Throwable -> L36
            if (r0 == 0) goto L38
            com.google.android.gms.ads.internal.util.client.VersionInfoParcel r0 = r3.g     // Catch: java.lang.Throwable -> L36
            int r0 = r0.c     // Catch: java.lang.Throwable -> L36
            com.google.android.gms.internal.ads.s7 r2 = com.google.android.gms.internal.ads.AbstractC2773w7.jb     // Catch: java.lang.Throwable -> L36
            com.google.android.gms.internal.ads.u7 r1 = r1.c     // Catch: java.lang.Throwable -> L36
            java.lang.Object r1 = r1.a(r2)     // Catch: java.lang.Throwable -> L36
            java.lang.Integer r1 = (java.lang.Integer) r1     // Catch: java.lang.Throwable -> L36
            int r1 = r1.intValue()     // Catch: java.lang.Throwable -> L36
            if (r0 >= r1) goto L3d
            goto L38
        L36:
            r0 = move-exception
            goto L53
        L38:
            java.lang.String r0 = "resume must be called on the main UI thread."
            com.google.android.gms.common.internal.u.d(r0)     // Catch: java.lang.Throwable -> L36
        L3d:
            com.google.android.gms.internal.ads.Tf r0 = r3.i     // Catch: java.lang.Throwable -> L36
            if (r0 == 0) goto L51
            com.google.android.gms.internal.ads.nh r0 = r0.c     // Catch: java.lang.Throwable -> L36
            r0.getClass()     // Catch: java.lang.Throwable -> L36
            com.google.android.gms.internal.ads.lh r1 = new com.google.android.gms.internal.ads.lh     // Catch: java.lang.Throwable -> L36
            r2 = 0
            r1.<init>(r2)     // Catch: java.lang.Throwable -> L36
            r0.j1(r1)     // Catch: java.lang.Throwable -> L36
            monitor-exit(r3)
            return
        L51:
            monitor-exit(r3)
            return
        L53:
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L36
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Jn.K():void");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void M0(com.google.android.gms.ads.internal.client.V v) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void N1(InterfaceC1622x interfaceC1622x) {
        if (f4()) {
            com.google.android.gms.common.internal.u.d("setAdListener must be called on the main UI thread.");
        }
        this.d.a.set(interfaceC1622x);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void O1(com.google.android.gms.ads.internal.client.T t) {
        com.google.android.gms.common.internal.u.d("setCorrelationIdProvider must be called on the main UI thread");
        this.f.u = t;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0038 A[Catch: all -> 0x0036, TryCatch #0 {all -> 0x0036, blocks: (B:3:0x0001, B:5:0x000f, B:7:0x0021, B:13:0x003d, B:15:0x0041, B:12:0x0038), top: B:22:0x0001 }] */
    @Override // com.google.android.gms.ads.internal.client.K
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized void P() {
        /*
            r3 = this;
            monitor-enter(r3)
            com.google.android.gms.internal.ads.I3 r0 = com.google.android.gms.internal.ads.U7.g     // Catch: java.lang.Throwable -> L36
            java.lang.Object r0 = r0.o()     // Catch: java.lang.Throwable -> L36
            java.lang.Boolean r0 = (java.lang.Boolean) r0     // Catch: java.lang.Throwable -> L36
            boolean r0 = r0.booleanValue()     // Catch: java.lang.Throwable -> L36
            if (r0 == 0) goto L38
            com.google.android.gms.internal.ads.s7 r0 = com.google.android.gms.internal.ads.AbstractC2773w7.fb     // Catch: java.lang.Throwable -> L36
            com.google.android.gms.ads.internal.client.r r1 = com.google.android.gms.ads.internal.client.r.d     // Catch: java.lang.Throwable -> L36
            com.google.android.gms.internal.ads.u7 r2 = r1.c     // Catch: java.lang.Throwable -> L36
            java.lang.Object r0 = r2.a(r0)     // Catch: java.lang.Throwable -> L36
            java.lang.Boolean r0 = (java.lang.Boolean) r0     // Catch: java.lang.Throwable -> L36
            boolean r0 = r0.booleanValue()     // Catch: java.lang.Throwable -> L36
            if (r0 == 0) goto L38
            com.google.android.gms.ads.internal.util.client.VersionInfoParcel r0 = r3.g     // Catch: java.lang.Throwable -> L36
            int r0 = r0.c     // Catch: java.lang.Throwable -> L36
            com.google.android.gms.internal.ads.s7 r2 = com.google.android.gms.internal.ads.AbstractC2773w7.jb     // Catch: java.lang.Throwable -> L36
            com.google.android.gms.internal.ads.u7 r1 = r1.c     // Catch: java.lang.Throwable -> L36
            java.lang.Object r1 = r1.a(r2)     // Catch: java.lang.Throwable -> L36
            java.lang.Integer r1 = (java.lang.Integer) r1     // Catch: java.lang.Throwable -> L36
            int r1 = r1.intValue()     // Catch: java.lang.Throwable -> L36
            if (r0 >= r1) goto L3d
            goto L38
        L36:
            r0 = move-exception
            goto L53
        L38:
            java.lang.String r0 = "pause must be called on the main UI thread."
            com.google.android.gms.common.internal.u.d(r0)     // Catch: java.lang.Throwable -> L36
        L3d:
            com.google.android.gms.internal.ads.Tf r0 = r3.i     // Catch: java.lang.Throwable -> L36
            if (r0 == 0) goto L51
            com.google.android.gms.internal.ads.nh r0 = r0.c     // Catch: java.lang.Throwable -> L36
            r0.getClass()     // Catch: java.lang.Throwable -> L36
            com.google.android.gms.internal.ads.kh r1 = new com.google.android.gms.internal.ads.kh     // Catch: java.lang.Throwable -> L36
            r2 = 0
            r1.<init>(r2)     // Catch: java.lang.Throwable -> L36
            r0.j1(r1)     // Catch: java.lang.Throwable -> L36
            monitor-exit(r3)
            return
        L51:
            monitor-exit(r3)
            return
        L53:
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L36
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Jn.P():void");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void W1(zzfw zzfwVar) {
        try {
            if (f4()) {
                com.google.android.gms.common.internal.u.d("setVideoOptions must be called on the main UI thread.");
            }
            this.f.d = zzfwVar;
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void X3(boolean z) {
        try {
            if (f4()) {
                com.google.android.gms.common.internal.u.d("setManualImpressionsEnabled must be called from the main thread.");
            }
            this.f.e = z;
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void Y() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void Y0(zzm zzmVar, com.google.android.gms.ads.internal.client.A a) {
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

    public final synchronized boolean e4(zzm zzmVar) {
        try {
            if (f4()) {
                com.google.android.gms.common.internal.u.d("loadAd must be called on the main UI thread.");
            }
            com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
            Context context = this.a;
            if (!com.google.android.gms.ads.internal.util.F.g(context) || zzmVar.s != null) {
                AbstractC1795We.g(context, zzmVar.f);
                return this.b.b(zzmVar, this.c, null, new Os(this, 26));
            }
            com.google.android.gms.ads.internal.util.client.i.e("Failed to load the ad because app ID is missing.");
            Ln ln = this.d;
            if (ln != null) {
                ln.m0(AbstractC1972di.x(4, null, null));
            }
            return false;
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void f1() {
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0024  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean f4() {
        /*
            r6 = this;
            com.google.android.gms.internal.ads.I3 r0 = com.google.android.gms.internal.ads.U7.f
            java.lang.Object r0 = r0.o()
            java.lang.Boolean r0 = (java.lang.Boolean) r0
            boolean r0 = r0.booleanValue()
            r1 = 1
            r2 = 0
            if (r0 == 0) goto L24
            com.google.android.gms.internal.ads.s7 r0 = com.google.android.gms.internal.ads.AbstractC2773w7.hb
            com.google.android.gms.ads.internal.client.r r3 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r3 = r3.c
            java.lang.Object r0 = r3.a(r0)
            java.lang.Boolean r0 = (java.lang.Boolean) r0
            boolean r0 = r0.booleanValue()
            if (r0 == 0) goto L24
            r0 = r1
            goto L25
        L24:
            r0 = r2
        L25:
            com.google.android.gms.ads.internal.util.client.VersionInfoParcel r3 = r6.g
            int r3 = r3.c
            com.google.android.gms.internal.ads.s7 r4 = com.google.android.gms.internal.ads.AbstractC2773w7.ib
            com.google.android.gms.ads.internal.client.r r5 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r5 = r5.c
            java.lang.Object r4 = r5.a(r4)
            java.lang.Integer r4 = (java.lang.Integer) r4
            int r4 = r4.intValue()
            if (r3 < r4) goto L3f
            if (r0 != 0) goto L3e
            goto L3f
        L3e:
            return r2
        L3f:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Jn.f4():boolean");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void g0() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void g3(InterfaceC1866b6 interfaceC1866b6) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized com.google.android.gms.ads.internal.client.zzr h() {
        com.google.android.gms.common.internal.u.d("getAdSize must be called on the main UI thread.");
        C1778Tf c1778Tf = this.i;
        if (c1778Tf != null) {
            return LA.e(this.a, Collections.singletonList(c1778Tf.c()));
        }
        return this.f.b;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final com.google.android.gms.ads.internal.client.P i() {
        com.google.android.gms.ads.internal.client.P p;
        Ln ln = this.d;
        synchronized (ln) {
            p = (com.google.android.gms.ads.internal.client.P) ln.b.get();
        }
        return p;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void i0() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final Bundle j() {
        com.google.android.gms.common.internal.u.d("getAdMetadata must be called on the main UI thread.");
        return new Bundle();
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void j0() {
        com.google.android.gms.common.internal.u.d("recordManualImpression must be called on the main UI thread.");
        C1778Tf c1778Tf = this.i;
        if (c1778Tf != null) {
            c1778Tf.p.a();
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void j3(InterfaceC1609n0 interfaceC1609n0) {
        if (f4()) {
            com.google.android.gms.common.internal.u.d("setPaidEventListener must be called on the main UI thread.");
        }
        try {
            if (!interfaceC1609n0.f()) {
                this.h.b();
            }
        } catch (RemoteException unused) {
            com.google.android.gms.ads.internal.util.client.i.k(3);
        }
        this.d.c.set(interfaceC1609n0);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized com.google.android.gms.ads.internal.client.v0 k() {
        com.google.android.gms.common.internal.u.d("getVideoController must be called from the main thread.");
        C1778Tf c1778Tf = this.i;
        com.google.android.gms.ads.internal.client.v0 v0VarZza = null;
        if (c1778Tf == null) {
            return null;
        }
        try {
            v0VarZza = c1778Tf.n.zza();
        } catch (zzfcw unused) {
        }
        return v0VarZza;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void k1(zzx zzxVar) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final com.google.android.gms.dynamic.a m() {
        if (f4()) {
            com.google.android.gms.common.internal.u.d("getAdFrame must be called on the main UI thread.");
        }
        return new com.google.android.gms.dynamic.b(this.b.f);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized com.google.android.gms.ads.internal.client.s0 n() {
        C1778Tf c1778Tf;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.H6)).booleanValue() && (c1778Tf = this.i) != null) {
            return c1778Tf.f;
        }
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void p1(D7 d7) {
        com.google.android.gms.common.internal.u.d("setOnCustomRenderedAdLoadedListener must be called on the main UI thread.");
        this.b.g = d7;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized String s() {
        Ug ug;
        C1778Tf c1778Tf = this.i;
        if (c1778Tf == null || (ug = c1778Tf.f) == null) {
            return null;
        }
        return ug.a;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void s1(com.google.android.gms.dynamic.a aVar) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized boolean t3() {
        C1778Tf c1778Tf = this.i;
        if (c1778Tf != null) {
            if (c1778Tf.b.q0) {
                return true;
            }
        }
        return false;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized String w() {
        return this.c;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0038 A[Catch: all -> 0x0036, TryCatch #0 {all -> 0x0036, blocks: (B:3:0x0001, B:5:0x000f, B:7:0x0021, B:13:0x003d, B:15:0x0041, B:12:0x0038), top: B:22:0x0001 }] */
    @Override // com.google.android.gms.ads.internal.client.K
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized void y() {
        /*
            r3 = this;
            monitor-enter(r3)
            com.google.android.gms.internal.ads.I3 r0 = com.google.android.gms.internal.ads.U7.e     // Catch: java.lang.Throwable -> L36
            java.lang.Object r0 = r0.o()     // Catch: java.lang.Throwable -> L36
            java.lang.Boolean r0 = (java.lang.Boolean) r0     // Catch: java.lang.Throwable -> L36
            boolean r0 = r0.booleanValue()     // Catch: java.lang.Throwable -> L36
            if (r0 == 0) goto L38
            com.google.android.gms.internal.ads.s7 r0 = com.google.android.gms.internal.ads.AbstractC2773w7.eb     // Catch: java.lang.Throwable -> L36
            com.google.android.gms.ads.internal.client.r r1 = com.google.android.gms.ads.internal.client.r.d     // Catch: java.lang.Throwable -> L36
            com.google.android.gms.internal.ads.u7 r2 = r1.c     // Catch: java.lang.Throwable -> L36
            java.lang.Object r0 = r2.a(r0)     // Catch: java.lang.Throwable -> L36
            java.lang.Boolean r0 = (java.lang.Boolean) r0     // Catch: java.lang.Throwable -> L36
            boolean r0 = r0.booleanValue()     // Catch: java.lang.Throwable -> L36
            if (r0 == 0) goto L38
            com.google.android.gms.ads.internal.util.client.VersionInfoParcel r0 = r3.g     // Catch: java.lang.Throwable -> L36
            int r0 = r0.c     // Catch: java.lang.Throwable -> L36
            com.google.android.gms.internal.ads.s7 r2 = com.google.android.gms.internal.ads.AbstractC2773w7.jb     // Catch: java.lang.Throwable -> L36
            com.google.android.gms.internal.ads.u7 r1 = r1.c     // Catch: java.lang.Throwable -> L36
            java.lang.Object r1 = r1.a(r2)     // Catch: java.lang.Throwable -> L36
            java.lang.Integer r1 = (java.lang.Integer) r1     // Catch: java.lang.Throwable -> L36
            int r1 = r1.intValue()     // Catch: java.lang.Throwable -> L36
            if (r0 >= r1) goto L3d
            goto L38
        L36:
            r0 = move-exception
            goto L53
        L38:
            java.lang.String r0 = "destroy must be called on the main UI thread."
            com.google.android.gms.common.internal.u.d(r0)     // Catch: java.lang.Throwable -> L36
        L3d:
            com.google.android.gms.internal.ads.Tf r0 = r3.i     // Catch: java.lang.Throwable -> L36
            if (r0 == 0) goto L51
            com.google.android.gms.internal.ads.nh r0 = r0.c     // Catch: java.lang.Throwable -> L36
            r0.getClass()     // Catch: java.lang.Throwable -> L36
            com.google.android.gms.internal.ads.mh r1 = new com.google.android.gms.internal.ads.mh     // Catch: java.lang.Throwable -> L36
            r2 = 0
            r1.<init>(r2)     // Catch: java.lang.Throwable -> L36
            r0.j1(r1)     // Catch: java.lang.Throwable -> L36
            monitor-exit(r3)
            return
        L51:
            monitor-exit(r3)
            return
        L53:
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L36
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Jn.y():void");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized String z() {
        Ug ug;
        C1778Tf c1778Tf = this.i;
        if (c1778Tf == null || (ug = c1778Tf.f) == null) {
            return null;
        }
        return ug.a;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final InterfaceC1622x zzi() {
        return this.d.j();
    }
}
