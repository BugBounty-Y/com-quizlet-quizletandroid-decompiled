package com.google.android.gms.internal.ads;

import android.content.Context;
import java.util.HashMap;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class Oj {
    public final C2023eq a;
    public final Executor b;
    public final C2406nk c;
    public final C1974dk d;
    public final Context e;
    public final Hk f;
    public final C2584rr g;
    public final C2107gm h;
    public final Ek i;

    public Oj(C2023eq c2023eq, Executor executor, C2406nk c2406nk, Context context, Hk hk, C2584rr c2584rr, C2107gm c2107gm, C1974dk c1974dk, Ek ek) {
        this.a = c2023eq;
        this.b = executor;
        this.c = c2406nk;
        this.e = context;
        this.f = hk;
        this.g = c2584rr;
        this.h = c2107gm;
        this.d = c1974dk;
        this.i = ek;
    }

    public static final void b(InterfaceC2529qe interfaceC2529qe) {
        interfaceC2529qe.O0("/videoClicked", AbstractC2346m9.h);
        C1669Be c1669BeL = interfaceC2529qe.L();
        synchronized (c1669BeL.d) {
            c1669BeL.r = true;
        }
        interfaceC2529qe.O0("/getNativeAdViewSignals", AbstractC2346m9.s);
        interfaceC2529qe.O0("/getNativeClickMeta", AbstractC2346m9.t);
    }

    public final void a(InterfaceC2529qe interfaceC2529qe, com.google.android.gms.ads.internal.a aVar, C1673Cc c1673Cc) {
        b(interfaceC2529qe);
        interfaceC2529qe.O0("/video", AbstractC2346m9.l);
        interfaceC2529qe.O0("/videoMeta", AbstractC2346m9.m);
        interfaceC2529qe.O0("/precache", new C2175i9(26));
        interfaceC2529qe.O0("/delayPageLoaded", AbstractC2346m9.p);
        interfaceC2529qe.O0("/instrument", AbstractC2346m9.n);
        interfaceC2529qe.O0("/log", AbstractC2346m9.g);
        Object obj = null;
        interfaceC2529qe.O0("/click", new C2217j9(0, obj, obj));
        if (this.a.b != null) {
            C1669Be c1669BeL = interfaceC2529qe.L();
            synchronized (c1669BeL.d) {
                c1669BeL.t = true;
            }
            interfaceC2529qe.O0("/open", new C2689u9(true != ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.rd)).booleanValue() ? null : aVar, null, null, null, null));
        } else {
            C1669Be c1669BeL2 = interfaceC2529qe.L();
            synchronized (c1669BeL2.d) {
                c1669BeL2.t = false;
            }
        }
        if (com.google.android.gms.ads.internal.j.C.y.e(interfaceC2529qe.getContext())) {
            HashMap map = new HashMap();
            if (interfaceC2529qe.e() != null) {
                map = interfaceC2529qe.e().w0;
            }
            interfaceC2529qe.O0("/logScionEvent", new C2217j9(1, interfaceC2529qe.getContext(), map));
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.rd)).booleanValue()) {
            interfaceC2529qe.L().w = aVar;
            interfaceC2529qe.L().y = c1673Cc;
        }
    }
}
