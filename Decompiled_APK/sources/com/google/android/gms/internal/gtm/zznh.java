package com.google.android.gms.internal.gtm;

import android.content.Context;
import android.content.pm.PackageManager;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zznh implements zzjm {
    private final Context zza;

    public zznh(Context context) {
        u.h(context);
        this.zza = context;
    }

    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 0);
        try {
            return new zzqq(Double.valueOf(this.zza.getPackageManager().getPackageInfo(this.zza.getPackageName(), 0).versionCode));
        } catch (PackageManager.NameNotFoundException e) {
            zzhi.zza("Package name " + this.zza.getPackageName() + " not found. " + e.getMessage());
            return zzqs.zze;
        }
    }
}
