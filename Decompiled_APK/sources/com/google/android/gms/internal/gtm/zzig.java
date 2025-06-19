package com.google.android.gms.internal.gtm;

import android.content.Context;
import android.content.IntentFilter;
import androidx.core.content.c;

/* loaded from: classes2.dex */
final class zzig extends zzhz {
    private static final Object zza = new Object();
    private static zzig zzb;
    private Context zzc;
    private zzha zzd;
    private volatile zzgx zze;
    private zzic zzj;
    private zzhj zzk;
    private boolean zzf = true;
    private boolean zzg = false;
    private boolean zzh = false;
    private boolean zzi = true;
    private final zzia zzm = new zzia(this);
    private boolean zzl = false;

    private zzig() {
    }

    public static zzig zzf() {
        if (zzb == null) {
            zzb = new zzig();
        }
        return zzb;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final boolean zzn() {
        return this.zzl || !this.zzi;
    }

    @Override // com.google.android.gms.internal.gtm.zzhz
    public final synchronized void zza() {
        if (zzn()) {
            return;
        }
        this.zzj.zzb();
    }

    @Override // com.google.android.gms.internal.gtm.zzhz
    public final synchronized void zzb(boolean z) {
        zzk(this.zzl, z);
    }

    public final synchronized zzha zze() {
        try {
            if (this.zzd == null) {
                Context context = this.zzc;
                if (context == null) {
                    throw new IllegalStateException("Cant get a store unless we have a context");
                }
                this.zzd = new zzhm(this.zzm, context);
            }
            if (this.zzj == null) {
                zzie zzieVar = new zzie(this, null);
                this.zzj = zzieVar;
                zzieVar.zzc(1800000L);
            }
            this.zzg = true;
            if (this.zzf) {
                zzi();
                this.zzf = false;
            }
            if (this.zzk == null) {
                zzhj zzhjVar = new zzhj(this);
                this.zzk = zzhjVar;
                Context context2 = this.zzc;
                IntentFilter intentFilter = new IntentFilter();
                intentFilter.addAction("android.net.conn.CONNECTIVITY_CHANGE");
                c.f(context2, zzhjVar, intentFilter, 4);
                IntentFilter intentFilter2 = new IntentFilter();
                intentFilter2.addAction("com.google.analytics.RADIO_POWERED");
                intentFilter2.addCategory(context2.getPackageName());
                c.f(context2, zzhjVar, intentFilter2, 4);
            }
        } catch (Throwable th) {
            throw th;
        }
        return this.zzd;
    }

    public final synchronized void zzi() {
        if (!this.zzg) {
            zzhi.zzd("Dispatch call queued. Dispatch will run once initialization is complete.");
            this.zzf = true;
        } else {
            if (this.zzh) {
                return;
            }
            this.zzh = true;
            this.zze.zza(new zzib(this));
        }
    }

    public final synchronized void zzj(Context context, zzgx zzgxVar) {
        if (this.zzc == null) {
            this.zzc = context.getApplicationContext();
            if (this.zze == null) {
                this.zze = zzgxVar;
            }
        }
    }

    public final synchronized void zzk(boolean z, boolean z2) {
        boolean zZzn = zzn();
        this.zzl = z;
        this.zzi = z2;
        if (zzn() == zZzn) {
            return;
        }
        if (zzn()) {
            this.zzj.zza();
            zzhi.zzd("PowerSaveMode initiated.");
        } else {
            this.zzj.zzc(1800000L);
            zzhi.zzd("PowerSaveMode terminated.");
        }
    }
}
