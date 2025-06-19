package com.google.android.gms.internal.gtm;

import android.content.Context;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/* loaded from: classes2.dex */
public final class zzgr implements zzgw {
    private static zzgr zza;
    private static final Object zzb = new Object();
    private static final Set zzc = new HashSet(Arrays.asList("GET", "HEAD", "POST", "PUT"));
    private final zzgx zzd;
    private final zzhy zze;

    private zzgr(Context context) {
        zzgz zzgzVarZzd = zzgz.zzd(context);
        zzhy zzhyVar = new zzhy();
        this.zzd = zzgzVarZzd;
        this.zze = zzhyVar;
    }

    public static zzgw zza(Context context) {
        zzgr zzgrVar;
        synchronized (zzb) {
            try {
                if (zza == null) {
                    zza = new zzgr(context);
                }
                zzgrVar = zza;
            } catch (Throwable th) {
                throw th;
            }
        }
        return zzgrVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzgw
    public final boolean zzb(String str, String str2, String str3, Map map, String str4) {
        if (str2 != null && !zzc.contains(str2)) {
            zzhi.zze("Unsupport http method " + str2 + ". Drop the hit.");
            return false;
        }
        if (zzhp.zza().zzd() || this.zze.zza()) {
            this.zzd.zzb(str, str2, str3, map, str4);
            return true;
        }
        zzhi.zze("Too many hits sent too quickly (rate throttled).");
        return false;
    }
}
