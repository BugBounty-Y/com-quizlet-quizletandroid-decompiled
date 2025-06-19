package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.view.MotionEvent;
import android.view.View;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.lang.ref.WeakReference;
import java.util.concurrent.Executor;

/* renamed from: com.google.android.gms.internal.ads.mk, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2363mk {
    public final Vg a;
    public final C2404ni b;
    public final C2489ph c;
    public final C2746vh d;
    public final C2875yh e;
    public final Qh f;
    public final Executor g;
    public final C2361mi h;
    public final C1724Kf i;
    public final com.google.android.gms.ads.internal.a j;
    public final InterfaceC1679Dc k;
    public final P4 l;
    public final Mh m;
    public final C2107gm n;
    public final C2584rr o;
    public final Hk p;
    public final C2830xf q;
    public final C2535qk r;

    public C2363mk(Vg vg, C2489ph c2489ph, C2746vh c2746vh, C2875yh c2875yh, Qh qh, Executor executor, C2361mi c2361mi, C1724Kf c1724Kf, com.google.android.gms.ads.internal.a aVar, InterfaceC1679Dc interfaceC1679Dc, P4 p4, Mh mh, C2107gm c2107gm, C2584rr c2584rr, Hk hk, C2404ni c2404ni, C2830xf c2830xf, C2535qk c2535qk) {
        this.a = vg;
        this.c = c2489ph;
        this.d = c2746vh;
        this.e = c2875yh;
        this.f = qh;
        this.g = executor;
        this.h = c2361mi;
        this.i = c1724Kf;
        this.j = aVar;
        this.k = interfaceC1679Dc;
        this.l = p4;
        this.m = mh;
        this.n = c2107gm;
        this.o = c2584rr;
        this.p = hk;
        this.b = c2404ni;
        this.q = c2830xf;
        this.r = c2535qk;
    }

    public static final C2313ld b(InterfaceC2529qe interfaceC2529qe, String str, String str2, Bundle bundle) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.k2)).booleanValue()) {
            AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, bundle, "rendering-webview-load-html-start");
        }
        C2313ld c2313ld = new C2313ld();
        interfaceC2529qe.L().g = new C1732Mb(22, bundle, c2313ld);
        interfaceC2529qe.w0(str, str2);
        return c2313ld;
    }

    public final void a(InterfaceC2529qe interfaceC2529qe, boolean z, C2475p9 c2475p9, Bundle bundle) {
        N4 n4;
        C2601s7 c2601s7 = AbstractC2773w7.k2;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, bundle, "rendering-configure-webview-start");
        }
        interfaceC2529qe.L().q(new InterfaceC1582a() { // from class: com.google.android.gms.internal.ads.jk
            @Override // com.google.android.gms.ads.internal.client.InterfaceC1582a
            public final void onAdClicked() {
                this.a.a.onAdClicked();
            }
        }, this.d, this.e, new InterfaceC2043f9() { // from class: com.google.android.gms.internal.ads.kk
            @Override // com.google.android.gms.internal.ads.InterfaceC2043f9
            public final void zzb(String str, String str2) {
                this.a.f.zzb(str, str2);
            }
        }, new Xj(this, 2), z, c2475p9, this.j, new Os(this, 19), this.k, this.n, this.o, this.p, null, this.b, null, null, null, this.q);
        interfaceC2529qe.setOnTouchListener(new View.OnTouchListener() { // from class: com.google.android.gms.internal.ads.lk
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view, MotionEvent motionEvent) {
                C2363mk c2363mk = this.a;
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.aa)).booleanValue() && motionEvent != null && motionEvent.getAction() == 0) {
                    c2363mk.r.a = motionEvent;
                }
                c2363mk.j.b = true;
                if (view == null) {
                    return false;
                }
                view.performClick();
                return false;
            }
        });
        interfaceC2529qe.setOnClickListener(new ViewOnClickListenerC2354mb(this, 1));
        C2601s7 c2601s72 = AbstractC2773w7.K2;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue() && (n4 = this.l.b) != null) {
            n4.a(interfaceC2529qe.N());
        }
        C2361mi c2361mi = this.h;
        Executor executor = this.g;
        c2361mi.i1(interfaceC2529qe, executor);
        c2361mi.i1(new Lj(interfaceC2529qe, 2), executor);
        c2361mi.k1(interfaceC2529qe.N());
        interfaceC2529qe.O0("/trackActiveViewUnit", new C2217j9(5, this, interfaceC2529qe));
        C1724Kf c1724Kf = this.i;
        c1724Kf.getClass();
        c1724Kf.j = new WeakReference(interfaceC2529qe);
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s7)).booleanValue()) {
            AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, bundle, "rendering-configure-webview-end");
        }
    }
}
