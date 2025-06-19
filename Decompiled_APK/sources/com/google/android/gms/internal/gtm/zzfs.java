package com.google.android.gms.internal.gtm;

import android.os.Build;

/* loaded from: classes2.dex */
public abstract class zzfs {
    public static final int zza;

    static {
        zza = Build.VERSION.SDK_INT >= 31 ? 33554432 : 0;
    }
}
