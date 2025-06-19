package com.google.android.gms.measurement;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.PowerManager;
import android.util.SparseArray;
import com.google.android.gms.auth.api.signin.internal.h;
import com.google.android.gms.measurement.internal.I;
import com.google.android.gms.measurement.internal.Y;

/* loaded from: classes2.dex */
public final class AppMeasurementReceiver extends androidx.legacy.content.a {
    public h c;

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        if (this.c == null) {
            this.c = new h(this, 25);
        }
        h hVar = this.c;
        hVar.getClass();
        I i = Y.q(context, null, null).i;
        Y.k(i);
        if (intent == null) {
            i.j.f("Receiver called with null intent");
            return;
        }
        String action = intent.getAction();
        i.o.g("Local receiver got", action);
        if (!"com.google.android.gms.measurement.UPLOAD".equals(action)) {
            if ("com.android.vending.INSTALL_REFERRER".equals(action)) {
                i.j.f("Install Referrer Broadcasts are deprecated");
                return;
            }
            return;
        }
        Intent className = new Intent().setClassName(context, "com.google.android.gms.measurement.AppMeasurementService");
        className.setAction("com.google.android.gms.measurement.UPLOAD");
        i.o.f("Starting wakeful intent.");
        ((AppMeasurementReceiver) hVar.b).getClass();
        SparseArray sparseArray = androidx.legacy.content.a.a;
        synchronized (sparseArray) {
            try {
                int i2 = androidx.legacy.content.a.b;
                int i3 = i2 + 1;
                androidx.legacy.content.a.b = i3;
                if (i3 <= 0) {
                    androidx.legacy.content.a.b = 1;
                }
                className.putExtra("androidx.contentpager.content.wakelockid", i2);
                ComponentName componentNameStartService = context.startService(className);
                if (componentNameStartService == null) {
                    return;
                }
                PowerManager.WakeLock wakeLockNewWakeLock = ((PowerManager) context.getSystemService("power")).newWakeLock(1, "androidx.core:wake:" + componentNameStartService.flattenToShortString());
                wakeLockNewWakeLock.setReferenceCounted(false);
                wakeLockNewWakeLock.acquire(60000L);
                sparseArray.put(i2, wakeLockNewWakeLock);
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
