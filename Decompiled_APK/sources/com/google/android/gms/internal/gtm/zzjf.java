package com.google.android.gms.internal.gtm;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

/* loaded from: classes2.dex */
abstract class zzjf {
    private static final ScheduledExecutorService zza;

    static {
        zzfx.zza();
        zza = Executors.unconfigurableScheduledExecutorService(Executors.newScheduledThreadPool(1, new zzje()));
    }
}
