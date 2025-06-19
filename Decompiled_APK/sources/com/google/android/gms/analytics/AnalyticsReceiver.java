package com.google.android.gms.analytics;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import com.google.android.gms.internal.gtm.zzev;

/* loaded from: classes2.dex */
public final class AnalyticsReceiver extends BroadcastReceiver {
    public zzev a;

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) throws PackageManager.NameNotFoundException {
        if (this.a == null) {
            this.a = new zzev();
        }
        this.a.zza(context, intent);
    }
}
