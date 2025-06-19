package com.google.android.gms.internal.gtm;

import android.content.ComponentCallbacks2;
import android.content.res.Configuration;

/* loaded from: classes2.dex */
final class zzir implements ComponentCallbacks2 {
    final /* synthetic */ zzix zza;

    public zzir(zzix zzixVar) {
        this.zza = zzixVar;
    }

    @Override // android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration configuration) {
    }

    @Override // android.content.ComponentCallbacks
    public final void onLowMemory() {
    }

    @Override // android.content.ComponentCallbacks2
    public final void onTrimMemory(int i) {
        if (i == 20) {
            this.zza.zzf.execute(new zziq(this));
        }
    }
}
