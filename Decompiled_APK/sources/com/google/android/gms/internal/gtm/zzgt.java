package com.google.android.gms.internal.gtm;

import android.os.Bundle;
import android.os.RemoteException;
import android.os.SystemClock;
import com.google.android.gms.common.util.a;
import java.util.Date;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzgt implements a {
    private final Bundle zza;
    private final String zzb;
    private final Date zzc;
    private final String zzd;
    private Map zze;
    private boolean zzf;
    private final com.google.android.gms.tagmanager.zzck zzg;

    public zzgt(String str, Bundle bundle, String str2, Date date, boolean z, com.google.android.gms.tagmanager.zzck zzckVar) {
        this.zzb = str;
        this.zza = bundle == null ? new Bundle() : bundle;
        this.zzc = date;
        this.zzd = str2;
        this.zzf = z;
        this.zzg = zzckVar;
    }

    @Override // com.google.android.gms.common.util.a
    public final long currentTimeMillis() {
        return this.zzc.getTime();
    }

    @Override // com.google.android.gms.common.util.a
    public final long elapsedRealtime() {
        return SystemClock.elapsedRealtime();
    }

    public final Bundle zza() {
        return this.zza;
    }

    public final String zzb() {
        return this.zzb;
    }

    public final String zzc() {
        return this.zzd;
    }

    public final Map zzd() {
        if (this.zze == null) {
            try {
                this.zze = this.zzg.zzb();
            } catch (RemoteException e) {
                zzhi.zza("Error calling measurement proxy:".concat(String.valueOf(e.getMessage())));
            }
        }
        return this.zze;
    }

    public final void zze(boolean z) {
        this.zzf = false;
    }

    public final boolean zzf() {
        return this.zzf;
    }
}
