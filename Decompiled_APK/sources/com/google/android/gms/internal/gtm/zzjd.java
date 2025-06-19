package com.google.android.gms.internal.gtm;

import android.content.Context;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
abstract class zzjd {
    private static volatile ExecutorService zza;

    public static ExecutorService zza(Context context) {
        if (zza == null) {
            synchronized (zzjd.class) {
                try {
                    if (zza == null) {
                        zza = new zzgu(context, 1, 1, 0L, TimeUnit.MILLISECONDS, new LinkedBlockingQueue(), new zzjc());
                    }
                } finally {
                }
            }
        }
        return zza;
    }
}
