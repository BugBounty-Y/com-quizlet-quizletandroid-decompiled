package com.google.android.gms.internal.gtm;

import android.os.Handler;
import android.os.Message;

/* loaded from: classes2.dex */
final class zzid implements Handler.Callback {
    final /* synthetic */ zzie zza;

    public zzid(zzie zzieVar) {
        this.zza = zzieVar;
    }

    @Override // android.os.Handler.Callback
    public final boolean handleMessage(Message message) {
        if (message.what == 1 && zzig.zza.equals(message.obj)) {
            this.zza.zza.zzi();
            zzie zzieVar = this.zza;
            if (!zzieVar.zza.zzn()) {
                zzieVar.zzc(1800000L);
            }
        }
        return true;
    }
}
