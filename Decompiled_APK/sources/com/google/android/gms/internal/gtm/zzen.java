package com.google.android.gms.internal.gtm;

import android.annotation.SuppressLint;
import android.support.v4.media.session.a;
import android.util.Log;
import com.google.android.gms.analytics.b;

@Deprecated
/* loaded from: classes2.dex */
public abstract class zzen {
    private static volatile b zza = new zzct();

    @SuppressLint({"LogTagMismatch"})
    public static void zzb(String str, Object obj) {
        String string;
        zzeo zzeoVarZza = zzeo.zza();
        if (zzeoVarZza != null) {
            zzeoVarZza.zzJ(str, obj);
        } else if (zzf(3)) {
            if (obj != null) {
                StringBuilder sbX = a.x(str, ":");
                sbX.append((String) obj);
                string = sbX.toString();
            } else {
                string = str;
            }
            Log.e((String) zzeh.zzb.zzb(), string);
        }
        b bVar = zza;
        if (bVar != null) {
            bVar.error(str);
        }
    }

    public static void zzc(b bVar) {
        zza = bVar;
    }

    @SuppressLint({"LogTagMismatch"})
    public static void zze(String str) {
        zzeo zzeoVarZza = zzeo.zza();
        if (zzeoVarZza != null) {
            zzeoVarZza.zzQ(str);
        } else if (zzf(2)) {
            Log.w((String) zzeh.zzb.zzb(), str);
        }
        b bVar = zza;
        if (bVar != null) {
            bVar.warn(str);
        }
    }

    public static boolean zzf(int i) {
        return zza != null && zza.getLogLevel() <= i;
    }
}
