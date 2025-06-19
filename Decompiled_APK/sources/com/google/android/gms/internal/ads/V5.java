package com.google.android.gms.internal.ads;

import android.content.Context;
import androidx.appcompat.view.menu.RunnableC0069f;

/* loaded from: classes2.dex */
public final class V5 {
    public final Y5 a;
    public final W5 b = new W5("com.google.android.gms.ads.internal.appopen.client.IAppOpenFullScreenContentCallback");

    public V5(Y5 y5) {
        this.a = y5;
    }

    public static void a(Context context, String str, com.google.android.gms.ads.g gVar, C2578rl c2578rl) {
        com.google.android.gms.common.internal.u.i(context, "Context cannot be null.");
        com.google.android.gms.common.internal.u.i(str, "adUnitId cannot be null.");
        com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
        AbstractC2773w7.a(context);
        if (((Boolean) U7.d.o()).booleanValue()) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.hb)).booleanValue()) {
                com.google.android.gms.ads.internal.util.client.a.b.execute(new RunnableC0069f(3, context, str, gVar, c2578rl, false));
                return;
            }
        }
        new C2210j2(context, str, gVar.zza(), c2578rl).b();
    }
}
