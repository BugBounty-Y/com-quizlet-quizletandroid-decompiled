package com.google.android.gms.internal.gtm;

import android.content.ComponentName;
import android.os.RemoteException;
import com.google.android.gms.analytics.j;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.common.stats.a;
import java.util.Collections;

/* loaded from: classes2.dex */
public final class zzcb extends zzbr {
    private final zzca zza;
    private final zzcv zzb;
    private final zzfb zzc;
    private zzel zzd;

    public zzcb(zzbu zzbuVar) {
        super(zzbuVar);
        this.zzc = new zzfb(zzbuVar.zzr());
        this.zza = new zzca(this);
        this.zzb = new zzbx(this, zzbuVar);
    }

    public static /* synthetic */ void zzb(zzcb zzcbVar, ComponentName componentName) {
        j.a();
        if (zzcbVar.zzd != null) {
            zzcbVar.zzd = null;
            zzcbVar.zzO("Disconnected from device AnalyticsService", componentName);
            zzcbVar.zzs().zzk();
        }
    }

    public static /* synthetic */ void zzi(zzcb zzcbVar, zzel zzelVar) {
        j.a();
        zzcbVar.zzd = zzelVar;
        zzcbVar.zzj();
        zzcbVar.zzs().zzj();
    }

    private final void zzj() {
        this.zzc.zzb();
        zzw();
        this.zzb.zzg(((Long) zzeh.zzA.zzb()).longValue());
    }

    public final void zzc() {
        j.a();
        zzV();
        try {
            a.b().c(zzo(), this.zza);
        } catch (IllegalArgumentException | IllegalStateException unused) {
        }
        if (this.zzd != null) {
            this.zzd = null;
            zzs().zzk();
        }
    }

    @Override // com.google.android.gms.internal.gtm.zzbr
    public final void zzd() {
    }

    public final boolean zzf() {
        j.a();
        zzV();
        if (this.zzd != null) {
            return true;
        }
        zzel zzelVarZza = this.zza.zza();
        if (zzelVarZza == null) {
            return false;
        }
        this.zzd = zzelVarZza;
        zzj();
        return true;
    }

    public final boolean zzg() {
        j.a();
        zzV();
        return this.zzd != null;
    }

    public final boolean zzh(zzek zzekVar) {
        String strZzk;
        u.h(zzekVar);
        j.a();
        zzV();
        zzel zzelVar = this.zzd;
        if (zzelVar == null) {
            return false;
        }
        if (zzekVar.zzh()) {
            zzw();
            strZzk = zzcs.zzi();
        } else {
            zzw();
            strZzk = zzcs.zzk();
        }
        try {
            zzelVar.zzf(zzekVar.zzg(), zzekVar.zzd(), strZzk, Collections.EMPTY_LIST);
            zzj();
            return true;
        } catch (RemoteException unused) {
            zzN("Failed to send hits to AnalyticsService");
            return false;
        }
    }
}
