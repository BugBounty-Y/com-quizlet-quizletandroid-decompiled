package com.google.android.gms.internal.gtm;

import android.content.Context;
import android.os.Bundle;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.common.util.a;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class zzgm {
    private final Context zza;
    private final String zzb;
    private final String zzc;
    private final String zzd;
    private final zzhw zze;
    private final zzpe zzf;
    private final ExecutorService zzg;
    private final ScheduledExecutorService zzh;
    private final com.google.android.gms.tagmanager.zzck zzi;
    private final a zzj;
    private final zzgo zzk;
    private zzhv zzl;
    private volatile int zzm = 1;
    private List zzn = new ArrayList();
    private ScheduledFuture zzo = null;
    private boolean zzp = false;

    public zzgm(Context context, String str, String str2, String str3, zzhw zzhwVar, zzpe zzpeVar, ExecutorService executorService, ScheduledExecutorService scheduledExecutorService, com.google.android.gms.tagmanager.zzck zzckVar, a aVar, zzgo zzgoVar) {
        this.zza = context;
        u.h(str);
        this.zzb = str;
        u.h(zzhwVar);
        this.zze = zzhwVar;
        u.h(zzpeVar);
        this.zzf = zzpeVar;
        u.h(executorService);
        this.zzg = executorService;
        u.h(scheduledExecutorService);
        this.zzh = scheduledExecutorService;
        u.h(zzckVar);
        this.zzi = zzckVar;
        u.h(aVar);
        this.zzj = aVar;
        u.h(zzgoVar);
        this.zzk = zzgoVar;
        this.zzc = str3;
        this.zzd = str2;
        this.zzn.add(new zzgt("gtm.load", new Bundle(), "gtm", new Date(), false, zzckVar));
        zzhi.zzd("Container " + str + "is scheduled for loading.");
        executorService.execute(new zzgh(this, null));
    }

    public static /* bridge */ /* synthetic */ void zzr(zzgm zzgmVar, long j) {
        ScheduledFuture scheduledFuture = zzgmVar.zzo;
        if (scheduledFuture != null) {
            scheduledFuture.cancel(false);
        }
        zzhi.zzd("Refresh container " + zzgmVar.zzb + " in " + j + "ms.");
        zzgmVar.zzo = zzgmVar.zzh.schedule(new zzgf(zzgmVar), j, TimeUnit.MILLISECONDS);
    }

    public final void zzs() {
        this.zzg.execute(new zzge(this));
    }

    public final void zzt(zzgt zzgtVar) {
        this.zzg.execute(new zzgi(this, zzgtVar));
    }
}
