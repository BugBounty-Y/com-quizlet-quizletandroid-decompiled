package com.google.firebase;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import androidx.collection.C0207e;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public class g extends BroadcastReceiver {
    public static final AtomicReference b = new AtomicReference();
    public final Context a;

    public g(Context context) {
        this.a = context;
    }

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        synchronized (h.k) {
            try {
                Iterator it2 = ((C0207e) h.l.values()).iterator();
                while (it2.hasNext()) {
                    ((h) it2.next()).e();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        this.a.unregisterReceiver(this);
    }
}
