package com.google.android.gms.internal.gtm;

import android.content.Context;

/* loaded from: classes2.dex */
public final class zzhw {
    private final Context zza;
    private final String zzb;
    private final com.google.android.gms.tagmanager.zzck zzc;
    private final com.google.android.gms.tagmanager.zzcb zzd;

    public zzhw(Context context, com.google.android.gms.tagmanager.zzck zzckVar, com.google.android.gms.tagmanager.zzcb zzcbVar, String str) {
        this.zza = context.getApplicationContext();
        this.zzc = zzckVar;
        this.zzd = zzcbVar;
        this.zzb = str;
    }

    public final zzhv zza(zzpy zzpyVar, zzqh zzqhVar) {
        return new zzhv(this.zza, this.zzb, zzpyVar, zzqhVar, this.zzc, this.zzd);
    }
}
