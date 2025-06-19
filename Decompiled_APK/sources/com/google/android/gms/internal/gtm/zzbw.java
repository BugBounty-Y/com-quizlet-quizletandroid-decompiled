package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class zzbw {
    private final String zza;
    private final String zzb;
    private final boolean zzc;
    private long zzd;
    private final Map zze;

    public zzbw(long j, String str, String str2, boolean z, long j2, Map map) {
        u.e(str);
        u.e(str2);
        this.zza = str;
        this.zzb = str2;
        this.zzc = z;
        this.zzd = j2;
        if (map != null) {
            this.zze = new HashMap(map);
        } else {
            this.zze = Collections.EMPTY_MAP;
        }
    }

    public final long zza() {
        return this.zzd;
    }

    public final String zzb() {
        return this.zza;
    }

    public final String zzc() {
        return this.zzb;
    }

    public final Map zzd() {
        return this.zze;
    }

    public final void zze(long j) {
        this.zzd = j;
    }

    public final boolean zzf() {
        return this.zzc;
    }
}
