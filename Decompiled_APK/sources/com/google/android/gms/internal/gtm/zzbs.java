package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.c;

/* loaded from: classes2.dex */
public abstract class zzbs {
    public static final String zza;
    public static final String zzb;

    static {
        String strReplaceAll = String.valueOf(c.a / 1000).replaceAll("(\\d+)(\\d)(\\d\\d)", "$1.$2.$3");
        zza = strReplaceAll;
        zzb = "ma".concat(String.valueOf(strReplaceAll));
    }
}
