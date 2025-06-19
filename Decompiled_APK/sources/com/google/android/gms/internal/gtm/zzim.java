package com.google.android.gms.internal.gtm;

import android.os.Bundle;

/* loaded from: classes2.dex */
final class zzim extends com.google.android.gms.tagmanager.zzcd {
    final /* synthetic */ zzix zza;

    public zzim(zzix zzixVar) {
        this.zza = zzixVar;
    }

    @Override // com.google.android.gms.tagmanager.zzce
    public final void zze(String str, String str2, Bundle bundle, long j) {
        if (str.endsWith("+gtm")) {
            return;
        }
        this.zza.zzf.execute(new zzil(this, str2, bundle, str.concat("+gtm"), j, str));
    }
}
