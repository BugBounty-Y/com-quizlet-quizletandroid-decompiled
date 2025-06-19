package com.google.android.gms.internal.gtm;

import android.content.Context;
import com.google.android.gms.common.util.c;

/* loaded from: classes2.dex */
abstract class zzgp {
    public static void zza(String str, Context context) {
        zzhi.zza(str);
        c.a(context, new RuntimeException(str));
        zzhi.zzd("Failed to report crash");
    }

    public static void zzb(String str, Throwable th, Context context) {
        zzhi.zzb(str, th);
        c.a(context, th);
        zzhi.zzd("Failed to report crash");
    }

    public static void zzc(String str, Context context) {
        zzhi.zze(str);
        c.a(context, new RuntimeException(str));
        zzhi.zzd("Failed to report crash");
    }
}
