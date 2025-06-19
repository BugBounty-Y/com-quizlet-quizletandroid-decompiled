package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import android.os.RemoteException;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import com.google.android.gms.ads.internal.client.InterfaceC1609n0;
import com.google.android.gms.ads.internal.client.InterfaceC1619u;
import com.google.android.gms.ads.internal.client.InterfaceC1622x;
import com.google.android.gms.ads.internal.client.zzfw;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.internal.client.zzx;
import java.util.Collections;

/* loaded from: classes2.dex */
public final class Gn extends com.google.android.gms.ads.internal.client.J {
    public final Context a;
    public final InterfaceC1622x b;
    public final C2023eq c;
    public final C1778Tf d;
    public final FrameLayout e;
    public final Hk f;

    public Gn(Context context, InterfaceC1622x interfaceC1622x, C2023eq c2023eq, C1778Tf c1778Tf, Hk hk) {
        this.a = context;
        this.b = interfaceC1622x;
        this.c = c2023eq;
        this.d = c1778Tf;
        this.f = hk;
        FrameLayout frameLayout = new FrameLayout(context);
        frameLayout.removeAllViews();
        com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
        frameLayout.addView(c1778Tf.k, new ViewGroup.LayoutParams(-1, -1));
        frameLayout.setMinimumHeight(h().c);
        frameLayout.setMinimumWidth(h().f);
        this.e = frameLayout;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A0(com.google.android.gms.ads.internal.client.P p) {
        Ln ln = this.c.c;
        if (ln != null) {
            ln.o(p);
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A1(com.google.android.gms.ads.internal.client.zzr zzrVar) {
        FrameLayout frameLayout;
        InterfaceC2529qe interfaceC2529qe;
        com.google.android.gms.common.internal.u.d("setAdSize must be called on the main UI thread.");
        C1778Tf c1778Tf = this.d;
        if (c1778Tf == null || (frameLayout = this.e) == null || (interfaceC2529qe = c1778Tf.l) == null) {
            return;
        }
        interfaceC2529qe.k0(com.bumptech.glide.load.engine.cache.f.a(zzrVar));
        frameLayout.setMinimumHeight(zzrVar.c);
        frameLayout.setMinimumWidth(zzrVar.f);
        c1778Tf.s = zzrVar;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A3(InterfaceC1619u interfaceC1619u) {
        com.google.android.gms.ads.internal.util.client.i.g("setAdClickListener is not supported in Ad Manager AdView returned by AdLoader.");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void E1(C2097gc c2097gc) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final boolean F3() {
        return false;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void H() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final boolean I2(zzm zzmVar) {
        com.google.android.gms.ads.internal.util.client.i.g("loadAd is not supported for an Ad Manager AdView returned from AdLoader.");
        return false;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void J() {
        com.google.android.gms.ads.internal.util.client.i.g("setAdMetadataListener is not supported in Ad Manager AdView returned by AdLoader.");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void K() {
        com.google.android.gms.common.internal.u.d("destroy must be called on the main UI thread.");
        C2403nh c2403nh = this.d.c;
        c2403nh.getClass();
        c2403nh.j1(new C2317lh(null));
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void M0(com.google.android.gms.ads.internal.client.V v) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void N1(InterfaceC1622x interfaceC1622x) {
        com.google.android.gms.ads.internal.util.client.i.g("setAdListener is not supported in Ad Manager AdView returned by AdLoader.");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void O1(com.google.android.gms.ads.internal.client.T t) {
        com.google.android.gms.ads.internal.util.client.i.g("setCorrelationIdProvider is not supported in Ad Manager AdView returned by AdLoader.");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void P() {
        com.google.android.gms.common.internal.u.d("destroy must be called on the main UI thread.");
        C2403nh c2403nh = this.d.c;
        c2403nh.getClass();
        c2403nh.j1(new C2274kh(null));
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void W1(zzfw zzfwVar) {
        com.google.android.gms.ads.internal.util.client.i.g("setVideoOptions is not supported in Ad Manager AdView returned by AdLoader.");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void X3(boolean z) {
        com.google.android.gms.ads.internal.util.client.i.g("setManualImpressionsEnabled is not supported in Ad Manager AdView returned by AdLoader.");
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

    @Override // com.google.android.gms.ads.internal.client.K
    public final void f1() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void g0() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void g3(InterfaceC1866b6 interfaceC1866b6) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final com.google.android.gms.ads.internal.client.zzr h() {
        com.google.android.gms.common.internal.u.d("getAdSize must be called on the main UI thread.");
        return LA.e(this.a, Collections.singletonList(this.d.c()));
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final com.google.android.gms.ads.internal.client.P i() {
        return this.c.n;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void i0() {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final Bundle j() {
        com.google.android.gms.ads.internal.util.client.i.g("getAdMetadata is not supported in Ad Manager AdView returned by AdLoader.");
        return new Bundle();
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void j0() {
        this.d.p.a();
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void j3(InterfaceC1609n0 interfaceC1609n0) {
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Ab)).booleanValue()) {
            com.google.android.gms.ads.internal.util.client.i.g("setOnPaidEventListener is not supported in Ad Manager AdView returned by AdLoader.");
            return;
        }
        Ln ln = this.c.c;
        if (ln != null) {
            try {
                if (!interfaceC1609n0.f()) {
                    this.f.b();
                }
            } catch (RemoteException unused) {
                com.google.android.gms.ads.internal.util.client.i.k(3);
            }
            ln.c.set(interfaceC1609n0);
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final com.google.android.gms.ads.internal.client.v0 k() {
        C1778Tf c1778Tf = this.d;
        c1778Tf.getClass();
        try {
            return c1778Tf.n.zza();
        } catch (zzfcw unused) {
            return null;
        }
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void k1(zzx zzxVar) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final com.google.android.gms.dynamic.a m() {
        return new com.google.android.gms.dynamic.b(this.e);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final com.google.android.gms.ads.internal.client.s0 n() {
        return this.d.f;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void p1(D7 d7) {
        com.google.android.gms.ads.internal.util.client.i.g("setOnCustomRenderedAdLoadedListener is not supported in Ad Manager AdView returned by AdLoader.");
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final String s() {
        Ug ug = this.d.f;
        if (ug != null) {
            return ug.a;
        }
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void s1(com.google.android.gms.dynamic.a aVar) {
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final boolean t3() {
        C1778Tf c1778Tf = this.d;
        return c1778Tf != null && c1778Tf.b.q0;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final String w() {
        return this.c.f;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void y() {
        com.google.android.gms.common.internal.u.d("destroy must be called on the main UI thread.");
        C2403nh c2403nh = this.d.c;
        c2403nh.getClass();
        c2403nh.j1(new C2360mh(null));
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final String z() {
        Ug ug = this.d.f;
        if (ug != null) {
            return ug.a;
        }
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final InterfaceC1622x zzi() {
        return this.b;
    }
}
