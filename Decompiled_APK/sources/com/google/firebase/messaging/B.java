package com.google.firebase.messaging;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class B extends BroadcastReceiver {
    public C a;

    @Override // android.content.BroadcastReceiver
    public final synchronized void onReceive(Context context, Intent intent) {
        C c = this.a;
        if (c == null) {
            return;
        }
        if (c.c()) {
            Log.isLoggable("FirebaseMessaging", 3);
            C c2 = this.a;
            c2.d.f.schedule(c2, 0L, TimeUnit.SECONDS);
            context.unregisterReceiver(this);
            this.a = null;
        }
    }
}
