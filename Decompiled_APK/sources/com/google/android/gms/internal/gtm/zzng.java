package com.google.android.gms.internal.gtm;

import android.content.Context;
import android.content.pm.PackageManager;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzng implements zzjm {
    private final Context zza;

    public zzng(Context context) {
        this.zza = context;
    }

    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 0);
        try {
            PackageManager packageManager = this.zza.getPackageManager();
            return new zzqz(packageManager.getApplicationLabel(packageManager.getApplicationInfo(this.zza.getPackageName(), 0)).toString());
        } catch (PackageManager.NameNotFoundException unused) {
            return new zzqz("");
        }
    }
}
