package com.google.android.gms.internal.gtm;

import android.content.Context;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzbv {
    private final Context zza;
    private final Context zzb;

    public zzbv(Context context) {
        u.h(context);
        Context applicationContext = context.getApplicationContext();
        u.i(applicationContext, "Application context can't be null");
        this.zza = applicationContext;
        this.zzb = applicationContext;
    }

    public final Context zza() {
        return this.zza;
    }

    public final Context zzb() {
        return this.zzb;
    }
}
