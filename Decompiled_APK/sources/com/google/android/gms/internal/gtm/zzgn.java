package com.google.android.gms.internal.gtm;

import android.content.Context;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.common.util.b;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;

/* loaded from: classes2.dex */
public final class zzgn {
    private final Context zza;
    private final zzpe zzb;
    private final ExecutorService zzc;
    private final ScheduledExecutorService zzd;
    private final com.google.android.gms.tagmanager.zzck zze;
    private final com.google.android.gms.tagmanager.zzcb zzf;

    public zzgn(Context context, com.google.android.gms.tagmanager.zzck zzckVar, com.google.android.gms.tagmanager.zzcb zzcbVar) {
        zzpe zzpeVar = new zzpe(context);
        ExecutorService executorServiceZza = zzjd.zza(context);
        ScheduledExecutorService scheduledExecutorService = zzjf.zza;
        u.h(context);
        this.zza = context.getApplicationContext();
        u.h(zzckVar);
        this.zze = zzckVar;
        u.h(zzcbVar);
        this.zzf = zzcbVar;
        this.zzb = zzpeVar;
        u.h(executorServiceZza);
        this.zzc = executorServiceZza;
        u.h(scheduledExecutorService);
        this.zzd = scheduledExecutorService;
    }

    public final zzgm zza(String str, String str2, String str3) {
        zzhw zzhwVar = new zzhw(this.zza, this.zze, this.zzf, str);
        zzgo zzgoVar = new zzgo(this.zza, str);
        return new zzgm(this.zza, str, str2, str3, zzhwVar, this.zzb, this.zzc, this.zzd, this.zze, b.a, zzgoVar);
    }
}
