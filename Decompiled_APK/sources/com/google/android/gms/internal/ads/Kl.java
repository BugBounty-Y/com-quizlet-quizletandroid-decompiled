package com.google.android.gms.internal.ads;

import android.content.Context;
import android.text.TextUtils;

/* loaded from: classes2.dex */
public final class Kl implements Jh {
    public final Context a;
    public final C1739Nc b;

    public Kl(Context context, C1739Nc c1739Nc) {
        this.a = context;
        this.b = c1739Nc;
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void J0(C1849aq c1849aq) {
        String str = ((Xp) c1849aq.b.b).e;
        if (TextUtils.isEmpty(str)) {
            return;
        }
        C1739Nc c1739Nc = this.b;
        Context context = this.a;
        c1739Nc.getClass();
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.v0)).booleanValue() && c1739Nc.e(context) && C1739Nc.g(context)) {
            synchronized (c1739Nc.i) {
            }
        }
        c1739Nc.k(context, "_aq", str, null);
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void r0(zzbvl zzbvlVar) {
    }
}
