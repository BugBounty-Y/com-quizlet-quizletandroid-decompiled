package com.google.android.gms.internal.gtm;

import android.util.Log;

/* loaded from: classes2.dex */
public abstract class zzhi {
    public static void zza(String str) {
        if (zzgq.zza(6)) {
            Log.e("GoogleTagManager", str);
        }
    }

    public static void zzb(String str, Throwable th) {
        if (zzgq.zza(6)) {
            Log.e("GoogleTagManager", str, th);
        }
    }

    public static void zzc(String str) {
        if (zzgq.zza(4)) {
            Log.i("GoogleTagManager", str);
        }
    }

    public static void zzd(String str) {
        zzgq.zza(2);
    }

    public static void zze(String str) {
        if (zzgq.zza(5)) {
            Log.w("GoogleTagManager", str);
        }
    }

    public static void zzf(String str, Throwable th) {
        if (zzgq.zza(5)) {
            Log.w("GoogleTagManager", str, th);
        }
    }
}
