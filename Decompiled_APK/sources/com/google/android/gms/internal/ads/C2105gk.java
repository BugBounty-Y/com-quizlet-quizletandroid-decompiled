package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import java.lang.ref.WeakReference;

/* renamed from: com.google.android.gms.internal.ads.gk, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2105gk extends AbstractC2359mg {
    public final Context j;
    public final WeakReference k;
    public final Ai l;
    public final Kq m;
    public final C2058fh n;
    public final C2746vh o;
    public final C2745vg p;
    public final BinderC2913zc q;
    public final C2585rs r;
    public final C1936cq s;
    public boolean t;

    public C2105gk(com.google.android.datatransport.cct.internal.s sVar, Context context, InterfaceC2529qe interfaceC2529qe, Ai ai, Kq kq, C2058fh c2058fh, C2746vh c2746vh, C2745vg c2745vg, Vp vp, C2585rs c2585rs, C1936cq c1936cq) {
        super(sVar);
        this.t = false;
        this.j = context;
        this.l = ai;
        this.k = new WeakReference(interfaceC2529qe);
        this.m = kq;
        this.n = c2058fh;
        this.o = c2746vh;
        this.p = c2745vg;
        this.r = c2585rs;
        zzbwj zzbwjVar = vp.l;
        this.q = new BinderC2913zc(zzbwjVar != null ? zzbwjVar.a : "", zzbwjVar != null ? zzbwjVar.b : 1);
        this.s = c1936cq;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void b(Activity activity, boolean z) {
        com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
        Ai ai = this.l;
        boolean zK = com.google.android.gms.ads.internal.util.F.k(ai.mo17zza());
        Context context = this.j;
        C2058fh c2058fh = this.n;
        if (!zK) {
            C2601s7 c2601s7 = AbstractC2773w7.H0;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && com.google.android.gms.ads.internal.util.F.f(context)) {
                com.google.android.gms.ads.internal.util.client.i.h("Rewarded ads that show when your app is in the background are a violation of AdMob policies and may lead to blocked ad serving. To learn more, visit https://goo.gle/admob-interstitial-policies");
                c2058fh.j();
                if (((Boolean) rVar.c.a(AbstractC2773w7.I0)).booleanValue()) {
                    this.r.a(((Xp) this.a.b.b).b);
                    return;
                }
                return;
            }
        }
        if (this.t) {
            com.google.android.gms.ads.internal.util.client.i.h("The rewarded ad have been showed.");
            c2058fh.a0(AbstractC1972di.x(10, null, null));
            return;
        }
        this.t = true;
        C1927ch c1927ch = new C1927ch(27);
        Kq kq = this.m;
        kq.j1(c1927ch);
        if (activity == null) {
            activity = context;
        }
        try {
            ai.k(z, activity, c2058fh);
            kq.a();
        } catch (zzdgh e) {
            c2058fh.E(e);
        }
    }

    public final void finalize() throws Throwable {
        try {
            InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.k.get();
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.F6)).booleanValue()) {
                if (!this.t && interfaceC2529qe != null) {
                    AbstractC2270kd.f.execute(new RunnableC1970dg(interfaceC2529qe, 4));
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
