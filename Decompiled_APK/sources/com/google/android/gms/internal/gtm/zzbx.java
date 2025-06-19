package com.google.android.gms.internal.gtm;

import com.google.android.gms.analytics.j;

/* loaded from: classes2.dex */
final class zzbx extends zzcv {
    final /* synthetic */ zzcb zza;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public zzbx(zzcb zzcbVar, zzbu zzbuVar) {
        super(zzbuVar);
        this.zza = zzcbVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzcv
    public final void zza() {
        j.a();
        zzcb zzcbVar = this.zza;
        if (zzcbVar.zzg()) {
            zzcbVar.zzN("Inactivity, disconnecting from device AnalyticsService");
            zzcbVar.zzc();
        }
    }
}
