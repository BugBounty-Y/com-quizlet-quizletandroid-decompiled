package com.quizlet.quizletandroid.receivers;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_barcode.Q6;
import com.quizlet.quizletandroid.managers.g;
import com.quizlet.quizletandroid.u;
import timber.log.c;

/* loaded from: classes3.dex */
public final class CoppaCompliantCampaignTrackingReceiver extends BroadcastReceiver {
    public static final /* synthetic */ int d = 0;
    public volatile boolean a = false;
    public final Object b = new Object();
    public g c;

    public final void a(Context context, Intent intent) {
        if (this.a) {
            return;
        }
        synchronized (this.b) {
            try {
                if (!this.a) {
                    this.c = (g) ((u) ((b) Q6.b(context))).Z0.get();
                    this.a = true;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        a(context, intent);
        BroadcastReceiver.PendingResult pendingResultGoAsync = goAsync();
        c.a.g("Installation campaign tracking event received: %s", intent);
        this.c.a(new a(this, context, intent, pendingResultGoAsync));
    }
}
