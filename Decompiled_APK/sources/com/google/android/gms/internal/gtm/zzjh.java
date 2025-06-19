package com.google.android.gms.internal.gtm;

import com.google.android.gms.analytics.b;

/* loaded from: classes2.dex */
final class zzjh implements b {
    @Override // com.google.android.gms.analytics.b
    public final void error(String str) {
        zzhi.zza(str);
    }

    @Override // com.google.android.gms.analytics.b
    public final int getLogLevel() {
        return 3;
    }

    @Override // com.google.android.gms.analytics.b
    public final void warn(String str) {
        zzhi.zze(str);
    }
}
