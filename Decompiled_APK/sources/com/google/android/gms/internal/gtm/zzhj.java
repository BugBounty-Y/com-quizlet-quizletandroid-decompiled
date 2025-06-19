package com.google.android.gms.internal.gtm;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;

/* loaded from: classes2.dex */
final class zzhj extends BroadcastReceiver {
    static final String zza = "com.google.android.gms.internal.gtm.zzhj";
    private final zzhz zzb;

    public zzhj(zzhz zzhzVar) {
        this.zzb = zzhzVar;
    }

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (!"android.net.conn.CONNECTIVITY_CHANGE".equals(action)) {
            if (!"com.google.analytics.RADIO_POWERED".equals(action) || intent.hasExtra(zza)) {
                return;
            }
            this.zzb.zza();
            return;
        }
        Bundle extras = intent.getExtras();
        Boolean boolValueOf = Boolean.FALSE;
        if (extras != null) {
            boolValueOf = Boolean.valueOf(intent.getExtras().getBoolean("noConnectivity"));
        }
        this.zzb.zzb(!boolValueOf.booleanValue());
    }
}
