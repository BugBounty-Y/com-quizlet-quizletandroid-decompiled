package com.quizlet.quizletandroid.receivers;

import android.content.Context;
import android.content.Intent;
import com.google.ads.conversiontracking.c;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.quizlet.quizletandroid.managers.e;
import com.quizlet.quizletandroid.managers.g;
import com.quizlet.quizletandroid.u;

/* loaded from: classes3.dex */
public class CoppaCompliantAdwordsConversionTrackingInstallReceiver extends c {
    public g a;

    public interface a {
    }

    public static void a(CoppaCompliantAdwordsConversionTrackingInstallReceiver coppaCompliantAdwordsConversionTrackingInstallReceiver, Context context, Intent intent, e eVar) {
        timber.log.c.a.a("Compliance state: %s", eVar);
        if (e.b.equals(eVar)) {
            return;
        }
        super.onReceive(context, intent);
    }

    @Override // com.google.ads.conversiontracking.c, android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        this.a = (g) ((u) ((a) K6.b(a.class, context.getApplicationContext()))).Z0.get();
        timber.log.c.a.a("Intent received: %s", intent);
        this.a.a(new com.quizlet.quizletandroid.receivers.a(this, context, intent));
    }
}
