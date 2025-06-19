package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.InterfaceC1609n0;
import com.google.android.gms.ads.internal.client.InterfaceC1619u;
import com.google.android.gms.ads.internal.client.InterfaceC1622x;
import com.google.android.gms.ads.internal.client.zzfw;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.internal.client.zzx;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;

/* loaded from: classes2.dex */
public final class On extends com.google.android.gms.ads.internal.client.J {
    public final com.google.android.gms.ads.internal.client.zzr a;
    public final Context b;
    public final Kp c;
    public final String d;
    public final VersionInfoParcel e;
    public final Ln f;
    public final Np g;
    public final P4 h;
    public final Hk i;
    public C2747vi j;
    public boolean k = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.J0)).booleanValue();

    public On(Context context, com.google.android.gms.ads.internal.client.zzr zzrVar, String str, Kp kp, Ln ln, Np np, VersionInfoParcel versionInfoParcel, P4 p4, Hk hk) {
        this.a = zzrVar;
        this.d = str;
        this.b = context;
        this.c = kp;
        this.f = ln;
        this.g = np;
        this.e = versionInfoParcel;
        this.h = p4;
        this.i = hk;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A0(com.google.android.gms.ads.internal.client.P p) {
        com.google.android.gms.common.internal.u.d("setAppEventListener must be called on the main UI thread.");
        this.f.o(p);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A1(com.google.android.gms.ads.internal.client.zzr zzrVar) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A3(InterfaceC1619u interfaceC1619u) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void E1(C2097gc c2097gc) {
        this.g.e.set(c2097gc);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized boolean F3() {
        return this.c.a();
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
            com.google.android.gms.internal.ads.I3 r0 = com.google.android.gms.internal.ads.U7.i     // Catch: java.lang.Throwable -> L31
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
            goto L9a
        L33:
            com.google.android.gms.ads.internal.util.client.VersionInfoParcel r1 = r5.e     // Catch: java.lang.Throwable -> L31
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
            boolean r1 = com.google.android.gms.ads.internal.util.F.g(r0)     // Catch: java.lang.Throwable -> L31
            r3 = 0
            if (r1 == 0) goto L73
            com.google.android.gms.ads.internal.client.zzc r1 = r6.s     // Catch: java.lang.Throwable -> L31
            if (r1 != 0) goto L73
            java.lang.String r6 = "Failed to load the ad because app ID is missing."
            com.google.android.gms.ads.internal.util.client.i.e(r6)     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.internal.ads.Ln r6 = r5.f     // Catch: java.lang.Throwable -> L31
            if (r6 == 0) goto L98
            r0 = 4
            com.google.android.gms.ads.internal.client.zze r0 = com.google.android.gms.internal.ads.AbstractC1972di.x(r0, r3, r3)     // Catch: java.lang.Throwable -> L31
            r6.m0(r0)     // Catch: java.lang.Throwable -> L31
            goto L98
        L73:
            boolean r1 = r5.e4()     // Catch: java.lang.Throwable -> L31
            if (r1 != 0) goto L98
            boolean r1 = r6.f     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.internal.ads.AbstractC1795We.g(r0, r1)     // Catch: java.lang.Throwable -> L31
            r5.j = r3     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.internal.ads.Kp r0 = r5.c     // Catch: java.lang.Throwable -> L31
            java.lang.String r1 = r5.d     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.ads.internal.client.zzr r2 = r5.a     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.internal.ads.Hp r3 = new com.google.android.gms.internal.ads.Hp     // Catch: java.lang.Throwable -> L31
            r3.<init>(r2)     // Catch: java.lang.Throwable -> L31
            com.google.android.gms.internal.ads.Ts r2 = new com.google.android.gms.internal.ads.Ts     // Catch: java.lang.Throwable -> L31
            r4 = 28
            r2.<init>(r5, r4)     // Catch: java.lang.Throwable -> L31
            boolean r6 = r0.b(r6, r1, r3, r2)     // Catch: java.lang.Throwable -> L31
            monitor-exit(r5)
            return r6
        L98:
            monitor-exit(r5)
            return r2
        L9a:
            monitor-exit(r5)     // Catch: java.lang.Throwable -> L31
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.On.I2(com.google.android.gms.ads.internal.client.zzm):boolean");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void J() {
        com.google.android.gms.common.internal.u.d("setAdMetadataListener must be called on the main UI thread.");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void K() {
        com.google.android.gms.common.internal.u.d("resume must be called on the main UI thread.");
        C2747vi c2747vi = this.j;
        if (c2747vi != null) {
            C2403nh c2403nh = c2747vi.c;
            c2403nh.getClass();
            c2403nh.j1(new C2317lh(null));
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void M0(com.google.android.gms.ads.internal.client.V v) {
        this.f.e.set(v);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void N1(InterfaceC1622x interfaceC1622x) {
        com.google.android.gms.common.internal.u.d("setAdListener must be called on the main UI thread.");
        this.f.a.set(interfaceC1622x);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void O1(com.google.android.gms.ads.internal.client.T t) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void P() {
        com.google.android.gms.common.internal.u.d("pause must be called on the main UI thread.");
        C2747vi c2747vi = this.j;
        if (c2747vi != null) {
            C2403nh c2403nh = c2747vi.c;
            c2403nh.getClass();
            c2403nh.j1(new C2274kh(null));
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void W1(zzfw zzfwVar) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void X3(boolean z) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void Y() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void Y0(zzm zzmVar, com.google.android.gms.ads.internal.client.A a) {
        this.f.d.set(a);
        I2(zzmVar);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void b0() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void c3(boolean z) {
        com.google.android.gms.common.internal.u.d("setImmersiveMode must be called on the main UI thread.");
        this.k = z;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized boolean e0() {
        com.google.android.gms.common.internal.u.d("isLoaded must be called on the main UI thread.");
        return e4();
    }

    public final synchronized boolean e4() {
        C2747vi c2747vi = this.j;
        if (c2747vi != null) {
            if (!c2747vi.n.b.get()) {
                return true;
            }
        }
        return false;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void f1() {
        com.google.android.gms.common.internal.u.d("showInterstitial must be called on the main UI thread.");
        if (this.j == null) {
            com.google.android.gms.ads.internal.util.client.i.h("Interstitial can not be shown before loaded.");
            this.f.r(AbstractC1972di.x(9, null, null));
        } else {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U2)).booleanValue()) {
                this.h.b.c(new Throwable().getStackTrace());
            }
            this.j.b(null, this.k);
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void g0() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void g3(InterfaceC1866b6 interfaceC1866b6) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final com.google.android.gms.ads.internal.client.zzr h() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final com.google.android.gms.ads.internal.client.P i() {
        com.google.android.gms.ads.internal.client.P p;
        Ln ln = this.f;
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
    public final void j0() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void j3(InterfaceC1609n0 interfaceC1609n0) {
        com.google.android.gms.common.internal.u.d("setPaidEventListener must be called on the main UI thread.");
        try {
            if (!interfaceC1609n0.f()) {
                this.i.b();
            }
        } catch (RemoteException unused) {
            com.google.android.gms.ads.internal.util.client.i.k(3);
        }
        this.f.c.set(interfaceC1609n0);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final com.google.android.gms.ads.internal.client.v0 k() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void k1(zzx zzxVar) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final com.google.android.gms.dynamic.a m() {
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized com.google.android.gms.ads.internal.client.s0 n() {
        C2747vi c2747vi;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.H6)).booleanValue() && (c2747vi = this.j) != null) {
            return c2747vi.f;
        }
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void p1(D7 d7) {
        com.google.android.gms.common.internal.u.d("setOnCustomRenderedAdLoadedListener must be called on the main UI thread.");
        this.c.f = d7;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized String s() {
        Ug ug;
        C2747vi c2747vi = this.j;
        if (c2747vi == null || (ug = c2747vi.f) == null) {
            return null;
        }
        return ug.a;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void s1(com.google.android.gms.dynamic.a aVar) {
        if (this.j == null) {
            com.google.android.gms.ads.internal.util.client.i.h("Interstitial can not be shown before loaded.");
            this.f.r(AbstractC1972di.x(9, null, null));
            return;
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U2)).booleanValue()) {
            this.h.b.c(new Throwable().getStackTrace());
        }
        this.j.b((Activity) com.google.android.gms.dynamic.b.I3(aVar), this.k);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized boolean t3() {
        return false;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized String w() {
        return this.d;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized void y() {
        com.google.android.gms.common.internal.u.d("destroy must be called on the main UI thread.");
        C2747vi c2747vi = this.j;
        if (c2747vi != null) {
            C2403nh c2403nh = c2747vi.c;
            c2403nh.getClass();
            c2403nh.j1(new C2360mh(null));
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final synchronized String z() {
        Ug ug;
        C2747vi c2747vi = this.j;
        if (c2747vi == null || (ug = c2747vi.f) == null) {
            return null;
        }
        return ug.a;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final InterfaceC1622x zzi() {
        return this.f.j();
    }
}
