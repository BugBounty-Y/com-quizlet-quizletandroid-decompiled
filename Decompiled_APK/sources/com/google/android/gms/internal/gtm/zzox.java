package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzox {
    private final String zza;
    private final String zzb;
    private final String zzc;
    private final boolean zzd;
    private final String zze;
    private final String zzf;

    public zzox(String str, String str2, String str3, boolean z, String str4, String str5) {
        u.h(str);
        this.zza = str;
        this.zzb = str2;
        this.zzc = str3;
        this.zzd = z;
        this.zze = str4;
        this.zzf = "";
    }

    public final String zza() {
        return this.zze;
    }

    public final String zzb() {
        return this.zza;
    }

    public final String zzc() {
        return this.zzb;
    }

    public final String zzd() {
        String str = this.zzc;
        return str != null ? a.l(str, "_", this.zza) : this.zza;
    }

    public final String zze() {
        return this.zzf;
    }

    public final String zzf() {
        return this.zzc;
    }

    public final boolean zzg() {
        return this.zzd;
    }
}
