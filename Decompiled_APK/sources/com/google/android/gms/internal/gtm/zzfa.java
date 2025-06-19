package com.google.android.gms.internal.gtm;

import android.annotation.TargetApi;
import android.app.job.JobParameters;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.Handler;
import com.comscore.streaming.EventType;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.stats.a;

/* loaded from: classes2.dex */
public final class zzfa {
    private static Boolean zza;
    private final Handler zzb;
    private final Context zzc;

    public zzfa(Context context) {
        u.h(context);
        this.zzc = context;
        this.zzb = new zzfy();
    }

    public static boolean zzh(Context context) throws PackageManager.NameNotFoundException {
        u.h(context);
        Boolean bool = zza;
        if (bool != null) {
            return bool.booleanValue();
        }
        boolean z = false;
        try {
            ServiceInfo serviceInfo = context.getPackageManager().getServiceInfo(new ComponentName(context, "com.google.android.gms.analytics.AnalyticsService"), 0);
            if (serviceInfo != null) {
                if (serviceInfo.enabled) {
                    z = true;
                }
            }
        } catch (PackageManager.NameNotFoundException unused) {
        }
        zza = Boolean.valueOf(z);
        return z;
    }

    public final int zza(Intent intent, int i, final int i2) {
        try {
            synchronized (zzev.zza) {
                try {
                    a aVar = zzev.zzb;
                    if (aVar != null && aVar.b()) {
                        aVar.c();
                    }
                } finally {
                }
            }
        } catch (SecurityException unused) {
        }
        zzbu zzbuVarZzg = zzbu.zzg(this.zzc);
        final zzeo zzeoVarZzm = zzbuVarZzg.zzm();
        if (intent == null) {
            zzeoVarZzm.zzQ("AnalyticsService started with null intent");
            return 2;
        }
        String action = intent.getAction();
        zzbuVarZzg.zzj();
        zzeoVarZzm.zzP("Local AnalyticsService called. startId, action", Integer.valueOf(i2), action);
        if ("com.google.android.gms.analytics.ANALYTICS_DISPATCH".equals(action)) {
            zzg(new Runnable() { // from class: com.google.android.gms.internal.gtm.zzew
                @Override // java.lang.Runnable
                public final void run() {
                    this.zza.zzc(i2, zzeoVarZzm);
                }
            });
        }
        return 2;
    }

    public final /* synthetic */ void zzc(int i, zzeo zzeoVar) {
        if (((zzez) this.zzc).callServiceStopSelfResult(i)) {
            zzeoVar.zzN("Local AnalyticsService processed last dispatch request");
        }
    }

    public final /* synthetic */ void zzd(zzeo zzeoVar, JobParameters jobParameters) {
        zzeoVar.zzN("AnalyticsJobService processed last dispatch request");
        ((zzez) this.zzc).zza(jobParameters, false);
    }

    public final void zze() {
        zzbu zzbuVarZzg = zzbu.zzg(this.zzc);
        zzeo zzeoVarZzm = zzbuVarZzg.zzm();
        zzbuVarZzg.zzj();
        zzeoVarZzm.zzN("Local AnalyticsService is starting up");
    }

    public final void zzf() {
        zzbu zzbuVarZzg = zzbu.zzg(this.zzc);
        zzeo zzeoVarZzm = zzbuVarZzg.zzm();
        zzbuVarZzg.zzj();
        zzeoVarZzm.zzN("Local AnalyticsService is shutting down");
    }

    public final void zzg(Runnable runnable) {
        zzbu.zzg(this.zzc).zzf().zze(new zzey(this, runnable));
    }

    @TargetApi(EventType.VIDEO)
    public final boolean zzi(final JobParameters jobParameters) {
        zzbu zzbuVarZzg = zzbu.zzg(this.zzc);
        final zzeo zzeoVarZzm = zzbuVarZzg.zzm();
        String string = jobParameters.getExtras().getString("action");
        zzbuVarZzg.zzj();
        zzeoVarZzm.zzO("Local AnalyticsJobService called. action", string);
        if (!"com.google.android.gms.analytics.ANALYTICS_DISPATCH".equals(string)) {
            return true;
        }
        zzg(new Runnable() { // from class: com.google.android.gms.internal.gtm.zzex
            @Override // java.lang.Runnable
            public final void run() {
                this.zza.zzd(zzeoVarZzm, jobParameters);
            }
        });
        return true;
    }
}
