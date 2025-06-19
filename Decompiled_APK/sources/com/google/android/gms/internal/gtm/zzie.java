package com.google.android.gms.internal.gtm;

import android.os.Handler;
import android.os.Message;

/* loaded from: classes2.dex */
final class zzie implements zzic {
    final /* synthetic */ zzig zza;
    private final Handler zzb;

    public /* synthetic */ zzie(zzig zzigVar, zzif zzifVar) {
        this.zza = zzigVar;
        this.zzb = new zzfy(zzigVar.zzc.getMainLooper(), new zzid(this));
    }

    private final Message zzd() {
        return this.zzb.obtainMessage(1, zzig.zza);
    }

    @Override // com.google.android.gms.internal.gtm.zzic
    public final void zza() {
        this.zzb.removeMessages(1, zzig.zza);
    }

    @Override // com.google.android.gms.internal.gtm.zzic
    public final void zzb() {
        this.zzb.removeMessages(1, zzig.zza);
        this.zzb.sendMessage(zzd());
    }

    @Override // com.google.android.gms.internal.gtm.zzic
    public final void zzc(long j) {
        this.zzb.removeMessages(1, zzig.zza);
        this.zzb.sendMessageDelayed(zzd(), 1800000L);
    }
}
