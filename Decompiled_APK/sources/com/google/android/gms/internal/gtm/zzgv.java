package com.google.android.gms.internal.gtm;

import android.text.TextUtils;
import java.util.Map;

/* loaded from: classes2.dex */
final class zzgv {
    private final long zza;
    private final long zzb;
    private String zzc;
    private String zzd;
    private Map zze;
    private String zzf;

    public zzgv(long j, long j2, long j3) {
        this.zza = j;
        this.zzb = j3;
    }

    public final long zza() {
        return this.zzb;
    }

    public final long zzb() {
        return this.zza;
    }

    public final String zzc() {
        return this.zzf;
    }

    public final String zzd() {
        return this.zzd;
    }

    public final String zze() {
        return this.zzc;
    }

    public final Map zzf() {
        return this.zze;
    }

    public final void zzg(String str) {
        this.zzf = str;
    }

    public final void zzh(Map map) {
        this.zze = map;
    }

    public final void zzi(String str) {
        this.zzd = str;
    }

    public final void zzj(String str) {
        if (str == null || TextUtils.isEmpty(str.trim())) {
            return;
        }
        this.zzc = str;
    }
}
