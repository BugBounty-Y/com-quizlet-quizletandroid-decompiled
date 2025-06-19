package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.C1600j;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.ads.internal.client.C1614q;

/* loaded from: classes2.dex */
public final class Q9 extends com.google.android.gms.ads.interstitial.a {
    public final Context a;
    public final com.google.android.gms.ads.internal.client.R0 b;
    public final com.google.android.gms.ads.internal.client.K c;
    public final long d;

    public Q9(Context context, String str) {
        BinderC2739va binderC2739va = new BinderC2739va();
        this.d = System.currentTimeMillis();
        this.a = context;
        this.b = com.google.android.gms.ads.internal.client.R0.a;
        C1608n c1608n = C1614q.f.b;
        com.google.android.gms.ads.internal.client.zzr zzrVar = new com.google.android.gms.ads.internal.client.zzr();
        c1608n.getClass();
        this.c = (com.google.android.gms.ads.internal.client.K) new C1600j(c1608n, context, zzrVar, str, binderC2739va).d(context, false);
    }

    @Override // com.google.android.gms.ads.interstitial.a
    public final void b(Activity activity) {
        if (activity == null) {
            com.google.android.gms.ads.internal.util.client.i.h("The activity for show is null, will proceed with show using the context provided when loading the ad.");
        }
        try {
            com.google.android.gms.ads.internal.client.K k = this.c;
            if (k != null) {
                k.s1(new com.google.android.gms.dynamic.b(activity));
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    public final void c(com.google.android.gms.ads.internal.client.y0 y0Var, com.google.android.gms.ads.w wVar) {
        try {
            com.google.android.gms.ads.internal.client.K k = this.c;
            if (k != null) {
                y0Var.n = this.d;
                com.google.android.gms.ads.internal.client.R0 r0 = this.b;
                Context context = this.a;
                r0.getClass();
                k.Y0(com.google.android.gms.ads.internal.client.R0.a(context, y0Var), new com.google.android.gms.ads.internal.client.P0(wVar, this));
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            wVar.a(new com.google.android.gms.ads.l(0, "Internal Error.", "com.google.android.gms.ads", null, null));
        }
    }
}
