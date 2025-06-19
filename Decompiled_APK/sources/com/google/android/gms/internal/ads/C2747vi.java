package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import java.lang.ref.WeakReference;

/* renamed from: com.google.android.gms.internal.ads.vi, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2747vi extends AbstractC2359mg {
    public final Context j;
    public final WeakReference k;
    public final Kq l;
    public final Ai m;
    public final C2745vg n;
    public final C2585rs o;
    public final C2058fh p;
    public final C2098gd q;
    public boolean r;

    public C2747vi(com.google.android.datatransport.cct.internal.s sVar, Context context, InterfaceC2529qe interfaceC2529qe, Kq kq, Ai ai, C2745vg c2745vg, C2585rs c2585rs, C2058fh c2058fh, C2098gd c2098gd) {
        super(sVar);
        this.r = false;
        this.j = context;
        this.k = new WeakReference(interfaceC2529qe);
        this.l = kq;
        this.m = ai;
        this.n = c2745vg;
        this.o = c2585rs;
        this.p = c2058fh;
        this.q = c2098gd;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void b(Activity activity, boolean z) {
        Vp vpE;
        int i;
        Kq kq = this.l;
        kq.j1(new C1927ch(27));
        com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
        Ai ai = this.m;
        boolean zK = com.google.android.gms.ads.internal.util.F.k(ai.mo17zza());
        Context context = this.j;
        C2058fh c2058fh = this.p;
        if (!zK) {
            C2601s7 c2601s7 = AbstractC2773w7.H0;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && com.google.android.gms.ads.internal.util.F.f(context)) {
                com.google.android.gms.ads.internal.util.client.i.h("Interstitials that show when your app is in the background are a violation of AdMob policies and may lead to blocked ad serving. To learn more, visit  https://goo.gle/admob-interstitial-policies");
                c2058fh.j();
                if (((Boolean) rVar.c.a(AbstractC2773w7.I0)).booleanValue()) {
                    this.o.a(((Xp) this.a.b.b).b);
                    return;
                }
                return;
            }
        }
        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.k.get();
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Sb)).booleanValue() && interfaceC2529qe != null && (vpE = interfaceC2529qe.e()) != null && vpE.r0) {
            C2098gd c2098gd = this.q;
            synchronized (c2098gd.a) {
                C2054fd c2054fd = c2098gd.d;
                synchronized (c2054fd.f) {
                    i = c2054fd.k;
                }
            }
            if (vpE.s0 != i) {
                com.google.android.gms.ads.internal.util.client.i.h("The interstitial consent form has been shown.");
                c2058fh.a0(AbstractC1972di.x(12, "The consent form has already been shown.", null));
                return;
            }
        }
        if (this.r) {
            com.google.android.gms.ads.internal.util.client.i.h("The interstitial ad has been shown.");
            c2058fh.a0(AbstractC1972di.x(10, null, null));
        }
        if (this.r) {
            return;
        }
        if (activity == null) {
            activity = context;
        }
        try {
            ai.k(z, activity, c2058fh);
            kq.a();
            this.r = true;
        } catch (zzdgh e) {
            c2058fh.E(e);
        }
    }

    public final void finalize() throws Throwable {
        try {
            InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.k.get();
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.F6)).booleanValue()) {
                if (!this.r && interfaceC2529qe != null) {
                    AbstractC2270kd.f.execute(new RunnableC1970dg(interfaceC2529qe, 2));
                }
            } else if (interfaceC2529qe != null) {
                interfaceC2529qe.destroy();
            }
            super.finalize();
        } catch (Throwable th) {
            super.finalize();
            throw th;
        }
    }
}
