package com.google.android.gms.ads.interstitial;

import android.app.Activity;
import android.content.Context;
import androidx.appcompat.view.menu.RunnableC0069f;
import com.google.android.gms.ads.g;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.Q9;
import com.google.android.gms.internal.ads.U7;

/* loaded from: classes2.dex */
public abstract class a {
    public static void a(Context context, String str, g gVar, b bVar) {
        u.i(context, "Context cannot be null.");
        u.i(str, "AdUnitId cannot be null.");
        u.i(gVar, "AdRequest cannot be null.");
        u.d("#008 Must be called on the main UI thread.");
        AbstractC2773w7.a(context);
        if (((Boolean) U7.i.o()).booleanValue()) {
            if (((Boolean) r.d.c.a(AbstractC2773w7.hb)).booleanValue()) {
                com.google.android.gms.ads.internal.util.client.a.b.execute(new RunnableC0069f(4, context, str, gVar, bVar, false));
                return;
            }
        }
        new Q9(context, str).c(gVar.zza(), bVar);
    }

    public abstract void b(Activity activity);
}
