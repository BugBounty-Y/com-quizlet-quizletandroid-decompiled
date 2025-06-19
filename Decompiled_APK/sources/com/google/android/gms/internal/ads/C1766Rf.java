package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;

/* renamed from: com.google.android.gms.internal.ads.Rf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1766Rf extends AbstractC2359mg {
    public final InterfaceC2529qe j;
    public final int k;
    public final Context l;
    public final Fi m;
    public final Ai n;
    public final Kq o;
    public final C2058fh p;
    public final boolean q;
    public final C2098gd r;
    public boolean s;

    public C1766Rf(com.google.android.datatransport.cct.internal.s sVar, Context context, InterfaceC2529qe interfaceC2529qe, int i, Fi fi, Ai ai, Kq kq, C2058fh c2058fh, C2098gd c2098gd) {
        super(sVar);
        this.s = false;
        this.j = interfaceC2529qe;
        this.l = context;
        this.k = i;
        this.m = fi;
        this.n = ai;
        this.o = kq;
        this.p = c2058fh;
        this.q = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.v5)).booleanValue();
        this.r = c2098gd;
    }

    public final void b() {
        C2403nh c2403nh = this.c;
        c2403nh.getClass();
        c2403nh.j1(new C2360mh(null));
        InterfaceC2529qe interfaceC2529qe = this.j;
        if (interfaceC2529qe != null) {
            interfaceC2529qe.destroy();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v15, types: [android.content.Context] */
    public final void c(Activity activity, boolean z) {
        InterfaceC2529qe interfaceC2529qe;
        Vp vpE;
        int i;
        Activity activity2 = activity;
        if (activity == null) {
            activity2 = this.l;
        }
        Kq kq = this.o;
        boolean z2 = this.q;
        if (z2) {
            kq.j1(new C1927ch(27));
        }
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        com.google.android.gms.ads.internal.util.F f = jVar.c;
        Ai ai = this.n;
        boolean zK = com.google.android.gms.ads.internal.util.F.k(ai.mo17zza());
        C2058fh c2058fh = this.p;
        if (!zK) {
            C2601s7 c2601s7 = AbstractC2773w7.H0;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && com.google.android.gms.ads.internal.util.F.f(activity2)) {
                com.google.android.gms.ads.internal.util.client.i.h("Interstitials that show when your app is in the background are a violation of AdMob policies and may lead to blocked ad serving. To learn more, visit https://goo.gle/admob-interstitial-policies");
                c2058fh.j();
                if (((Boolean) rVar.c.a(AbstractC2773w7.I0)).booleanValue()) {
                    new C2585rs(activity2.getApplicationContext(), jVar.t.o()).a(((Xp) this.a.b.b).b);
                    return;
                }
                return;
            }
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Sb)).booleanValue() && (interfaceC2529qe = this.j) != null && (vpE = interfaceC2529qe.e()) != null && vpE.r0) {
            C2098gd c2098gd = this.r;
            synchronized (c2098gd.a) {
                C2054fd c2054fd = c2098gd.d;
                synchronized (c2054fd.f) {
                    i = c2054fd.k;
                }
            }
            if (vpE.s0 != i) {
                com.google.android.gms.ads.internal.util.client.i.h("The app open consent form has been shown.");
                c2058fh.a0(AbstractC1972di.x(12, "The consent form has already been shown.", null));
                return;
            }
        }
        if (this.s) {
            com.google.android.gms.ads.internal.util.client.i.h("App open interstitial ad is already visible.");
            c2058fh.a0(AbstractC1972di.x(10, null, null));
        }
        if (this.s) {
            return;
        }
        try {
            ai.k(z, activity2, c2058fh);
            if (z2) {
                kq.a();
            }
            this.s = true;
        } catch (zzdgh e) {
            c2058fh.E(e);
        }
    }

    public final void d(int i, long j) {
        Fi fi = this.m;
        Fi fiA = ((Hk) fi.b).a();
        fiA.o("gqi", ((Xp) ((C1849aq) fi.c).b.b).b);
        fiA.o("action", "ad_closed");
        fiA.o("show_time", String.valueOf(j));
        fiA.o("ad_format", "app_open_ad");
        int i2 = i - 1;
        fiA.o("acr", i2 != 0 ? i2 != 1 ? i2 != 2 ? i2 != 3 ? i2 != 4 ? "u" : "ac" : "cb" : "cc" : "bb" : "h");
        fiA.x();
    }
}
