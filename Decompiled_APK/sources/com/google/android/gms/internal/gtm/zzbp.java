package com.google.android.gms.internal.gtm;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import com.google.android.gms.analytics.j;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzbp extends zzbr {
    private final zzcj zza;

    public zzbp(zzbu zzbuVar, zzbv zzbvVar) {
        super(zzbuVar);
        u.h(zzbvVar);
        this.zza = new zzcj(zzbuVar, zzbvVar);
    }

    public final long zza(zzbw zzbwVar) {
        zzV();
        u.h(zzbwVar);
        j.a();
        long jZzb = this.zza.zzb(zzbwVar, true);
        if (jZzb != 0) {
            return jZzb;
        }
        this.zza.zzk(zzbwVar);
        return 0L;
    }

    public final void zzc() {
        zzV();
        Context contextZzo = zzo();
        if (!zzev.zzb(contextZzo) || !zzfa.zzh(contextZzo)) {
            zze(null);
            return;
        }
        Intent intent = new Intent("com.google.android.gms.analytics.ANALYTICS_DISPATCH");
        intent.setComponent(new ComponentName(contextZzo, "com.google.android.gms.analytics.AnalyticsService"));
        contextZzo.startService(intent);
    }

    @Override // com.google.android.gms.internal.gtm.zzbr
    public final void zzd() {
        this.zza.zzW();
    }

    public final void zze(zzcy zzcyVar) {
        zzV();
        j jVarZzq = zzq();
        zzbn zzbnVar = new zzbn(this, zzcyVar);
        jVarZzq.getClass();
        jVarZzq.b.submit(zzbnVar);
    }

    public final void zzf(String str, Runnable runnable) {
        u.f(str, "campaign param can't be empty");
        j jVarZzq = zzq();
        zzbj zzbjVar = new zzbj(this, str, runnable);
        jVarZzq.getClass();
        jVarZzq.b.submit(zzbjVar);
    }

    public final void zzh(zzek zzekVar) {
        u.h(zzekVar);
        zzV();
        zzF("Hit delivery requested", zzekVar);
        j jVarZzq = zzq();
        zzbl zzblVar = new zzbl(this, zzekVar);
        jVarZzq.getClass();
        jVarZzq.b.submit(zzblVar);
    }

    public final void zzi() {
        j.a();
        this.zza.zzl();
    }

    public final void zzj() {
        j.a();
        this.zza.zzm();
    }

    public final void zzk() {
        zzV();
        j.a();
        j.a();
        zzcj zzcjVar = this.zza;
        zzcjVar.zzV();
        zzcjVar.zzN("Service disconnected");
    }

    public final void zzm() {
        this.zza.zzZ();
    }
}
