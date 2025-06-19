package com.google.android.gms.internal.gtm;

import android.content.Context;
import android.os.Process;
import com.google.android.gms.ads.identifier.a;
import com.google.android.gms.common.util.b;

/* loaded from: classes2.dex */
public final class zzgc {
    private static final Object zza = new Object();
    private static zzgc zzb;
    private volatile a zzg;
    private volatile long zzh;
    private volatile long zzi;
    private final Context zzj;
    private final com.google.android.gms.common.util.a zzk;
    private final Thread zzl;
    private volatile long zzc = 900000;
    private volatile long zzd = 30000;
    private volatile boolean zze = true;
    private volatile boolean zzf = false;
    private final Object zzm = new Object();
    private final zzgb zzn = new zzfz(this);

    public zzgc(Context context, zzgb zzgbVar, com.google.android.gms.common.util.a aVar) {
        this.zzk = aVar;
        if (context != null) {
            this.zzj = context.getApplicationContext();
        } else {
            this.zzj = null;
        }
        this.zzh = aVar.currentTimeMillis();
        this.zzl = new Thread(new zzga(this));
    }

    public static zzgc zzb(Context context) {
        if (zzb == null) {
            synchronized (zza) {
                try {
                    if (zzb == null) {
                        zzgc zzgcVar = new zzgc(context, null, b.a);
                        zzb = zzgcVar;
                        zzgcVar.zzl.start();
                    }
                } finally {
                }
            }
        }
        return zzb;
    }

    public static /* bridge */ /* synthetic */ void zze(zzgc zzgcVar) throws SecurityException, IllegalArgumentException {
        Process.setThreadPriority(10);
        while (true) {
            boolean z = zzgcVar.zzf;
            a aVarZza = zzgcVar.zze ? zzgcVar.zzn.zza() : null;
            if (aVarZza != null) {
                zzgcVar.zzg = aVarZza;
                zzgcVar.zzi = zzgcVar.zzk.currentTimeMillis();
                zzhi.zzc("Obtained fresh AdvertisingId info from GmsCore.");
            }
            synchronized (zzgcVar) {
                zzgcVar.notifyAll();
            }
            try {
                synchronized (zzgcVar.zzm) {
                    zzgcVar.zzm.wait(zzgcVar.zzc);
                }
            } catch (InterruptedException unused) {
                zzhi.zzc("sleep interrupted in AdvertiserDataPoller thread; continuing");
            }
        }
    }

    private final void zzg() {
        if (this.zzk.currentTimeMillis() - this.zzi > 3600000) {
            this.zzg = null;
        }
    }

    private final void zzh() {
        if (this.zzk.currentTimeMillis() - this.zzh > this.zzd) {
            synchronized (this.zzm) {
                this.zzm.notify();
            }
            this.zzh = this.zzk.currentTimeMillis();
        }
    }

    private final void zzi() {
        synchronized (this) {
            try {
                zzh();
                wait(500L);
            } catch (InterruptedException unused) {
            }
        }
    }

    public final String zzc() {
        if (this.zzg == null) {
            zzi();
        } else {
            zzh();
        }
        zzg();
        if (this.zzg == null) {
            return null;
        }
        return this.zzg.a;
    }

    public final boolean zzf() {
        if (this.zzg == null) {
            zzi();
        } else {
            zzh();
        }
        zzg();
        if (this.zzg == null) {
            return true;
        }
        return this.zzg.b;
    }
}
