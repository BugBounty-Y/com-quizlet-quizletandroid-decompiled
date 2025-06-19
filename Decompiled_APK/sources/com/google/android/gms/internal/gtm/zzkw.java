package com.google.android.gms.internal.gtm;

import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public final class zzkw implements zzjm {
    @Override // com.google.android.gms.internal.gtm.zzjm
    public final zzqo zzd(zzhx zzhxVar, zzqo... zzqoVarArr) {
        u.b(zzqoVarArr != null);
        u.b(zzqoVarArr.length == 2);
        zzqo zzqoVarZzc = zzra.zzc(zzhxVar, zzqoVarArr[0]);
        return zzjn.zzg(zzqoVarZzc) ? zzqoVarZzc : zzra.zzc(zzhxVar, zzqoVarArr[1]);
    }
}
