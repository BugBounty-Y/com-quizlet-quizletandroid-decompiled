package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Build;
import android.os.Looper;
import androidx.core.app.NotificationManagerCompat;

/* loaded from: classes2.dex */
public final class ZC {
    public final Context a;
    public final C1847ao b;
    public final Lr c;
    public final WC d;
    public Bt e;
    public Bt f;
    public final YC g;
    public final C2853y1 h;
    public final Looper i;
    public final int j;
    public final Wl k;
    public final int l;
    public final boolean m;
    public final OD n;
    public final long o;
    public final long p;
    public final boolean q;
    public boolean r;
    public final String s;
    public final SC t;

    public ZC(final Context context, Ts ts) {
        Lr lr = new Lr(ts, 6);
        WC wc = new WC(context);
        Bt bt = new Bt() { // from class: com.google.android.gms.internal.ads.XC
            @Override // com.google.android.gms.internal.ads.Bt
            public final Object zza() {
                return new VF(context);
            }
        };
        C2806wy c2806wy = new C2806wy(26);
        YC yc = new YC(context);
        C2853y1 c2853y1 = new C2853y1(19);
        context.getClass();
        this.a = context;
        this.c = lr;
        this.d = wc;
        this.e = bt;
        this.f = c2806wy;
        this.g = yc;
        this.h = c2853y1;
        String str = Yo.a;
        Looper looperMyLooper = Looper.myLooper();
        this.i = looperMyLooper == null ? Looper.getMainLooper() : looperMyLooper;
        this.k = Wl.b;
        this.l = 1;
        this.m = true;
        this.n = OD.c;
        int i = ND.a;
        this.t = new SC(Yo.t(20L), Yo.t(500L));
        this.b = C1847ao.a;
        this.o = 500L;
        this.p = 2000L;
        this.q = true;
        this.s = "";
        this.j = NotificationManagerCompat.IMPORTANCE_UNSPECIFIED;
        if (Build.VERSION.SDK_INT >= 35) {
            int i2 = VC.a;
        }
    }
}
