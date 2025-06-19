package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzll implements zzjm {
    private static zzhv zza;

    public zzll(zzhv zzhvVar) {
        zza = zzhvVar;
    }

    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 1);
        u.b(zzqoVarArr[0] instanceof zzqz);
        return zza.zzc(((zzqz) zzqoVarArr[0]).zzk());
    }
}
